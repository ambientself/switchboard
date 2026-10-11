# deploy/route-check/rbac-match.jq: which RBAC rules bound to a ServiceAccount grant a row of
# permissions.tsv, whatever their resourceNames (#60). A SubjectAccessReview names no resource,
# so it cannot see a rule limited by resourceNames: a workload able to mint tokens for one named
# ServiceAccount answers no. This reads the rules themselves. route-check.sh's step (c) and
# deploy/demo/demo.sh's operator checks both run it, so the two cannot drift. Both still ask the
# SubjectAccessReviews, which cover authorizers other than RBAC.
#
#   jq -n -r --rawfile permissions permissions.tsv --arg namespace NS --arg name NAME \
#     --argjson namespaces '["NS", ...]' -f rbac-match.jq <LISTS
#
# LISTS is a stream of objects {what, namespace, list}: `list` is what `kubectl get WHAT -o json`
# printed, `what` is clusterroles, clusterrolebindings, roles or rolebindings, and `namespace` is
# the namespace a Role or RoleBinding list was read in ("" for the cluster's). It needs exactly
# one ClusterRole list, one ClusterRoleBinding list, and one Role and one RoleBinding list for
# each of $namespaces. Lists for other namespaces are not counted.
#
# A binding counts when a subject is the ServiceAccount NAME in NS (kind ServiceAccount, or User
# system:serviceaccount:NS:NAME) or one of its groups (system:serviceaccounts,
# system:serviceaccounts:NS, system:authenticated). Its roleRef is resolved: a ClusterRoleBinding
# binds a ClusterRole; a RoleBinding binds a Role in its own namespace or a ClusterRole, whose
# rules then hold in that namespace. A roleRef that names nothing grants nothing.
#
# A rule grants a row when its verbs hold the row's verb or `*`, its apiGroups the row's group or
# `*`, and its resources `res` (for a row with no subresource), `res/sub`, `*` or `*/sub` (for a
# row with one), as the API server matches them. Its resourceNames are not read: a rule limited
# to one name still grants the row. A rule of nonResourceURLs names no resource and grants no
# row. A `namespaced` row counts the RoleBindings in $namespaces and the ClusterRoleBindings; a
# `cluster` row counts only the ClusterRoleBindings.
#
# It prints one line per row, tab-separated: `PASS`, the row and what was read; or `FAIL`, the
# row and each binding and rule that grants it. A list that is missing, repeated, or not a list
# of objects in the shape RBAC gives is an error (jq exits non-zero), never a list with nothing
# in it.

def unreadable($why): error("could not read \($why)");

# A field that is a list of strings, or absent.
def strings_of($what):
  if . == null then []
  elif type == "array" and all(.[]; type == "string") then .
  else unreadable("\($what): not a list of strings") end;

# A kubectl list's items, each an object.
def items_of($what):
  if type == "object" and (.items | type) == "array" and all(.items[]; type == "object") then .items
  else unreadable("the \($what): not a list of objects") end;

def name_of($what):
  if (.metadata | type) == "object" and (.metadata.name | type) == "string" then .metadata.name
  else unreadable("the \($what): an item has no name") end;

# A role's rules, each with its lists read.
def rules_of($what):
  (.rules | if . == null then [] elif type == "array" then . else unreadable("\($what): rules are not a list") end)
  | map(if type == "object" then . else unreadable("\($what): a rule is not an object") end
      | {verbs: (.verbs | strings_of("\($what): verbs")),
         apiGroups: (.apiGroups | strings_of("\($what): apiGroups")),
         resources: (.resources | strings_of("\($what): resources")),
         resourceNames: (.resourceNames | strings_of("\($what): resourceNames"))});

def subjects_of($what):
  .subjects
  | if . == null then [] elif type == "array" then . else unreadable("\($what): subjects are not a list") end
  | map(if type == "object" and (.kind | type) == "string" and (.name | type) == "string"
          and ((.namespace // "") | type) == "string" then .
        else unreadable("\($what): a subject has no kind or name") end);

def role_ref_of($what):
  if (.roleRef | type) == "object" and (.roleRef.kind | type) == "string" and (.roleRef.name | type) == "string"
  then .roleRef else unreadable("\($what): its roleRef has no kind or name") end;

# The rows of permissions.tsv, as route-check.sh reads them.
def rows:
  $permissions | split("\n") | map(select(length > 0 and (startswith("#") | not)) | split("\t"))
  | map(if length == 4 and (.[3] == "namespaced" or .[3] == "cluster") then .
        else error("permissions.tsv: bad row: \(join(" "))") end)
  | if length == 0 then error("permissions.tsv lists nothing") else . end
  | map(. as [$verb, $resource, $sub, $scope]
      | ($resource | index(".")) as $dot
      | {label: ("\($verb) \($resource)" + (if $sub == "-" then "" else "/\($sub)" end)),
         verb: $verb,
         resource: (if $dot then $resource[:$dot] else $resource end),
         group: (if $dot then $resource[$dot + 1:] else "" end),
         subresource: (if $sub == "-" then "" else $sub end),
         namespaced: ($scope == "namespaced")});

# A rule's entry matches what a row asks: itself, or the wildcard.
def named($want): . == $want or . == "*";

def grants($row):
  .resources != []
  and any(.verbs[]; named($row.verb))
  and any(.apiGroups[]; named($row.group))
  and (if $row.subresource == ""
       then any(.resources[]; named($row.resource))
       else any(.resources[]; named("\($row.resource)/\($row.subresource)") or . == "*/\($row.subresource)") end);

# The subject of a binding in namespace $bns ("" for a ClusterRoleBinding) that is the
# ServiceAccount or one of its groups; null when none is.
def subject_for($bns):
  ["system:serviceaccounts", "system:serviceaccounts:\($namespace)", "system:authenticated"] as $groups
  | first(.[] | select(
      (.kind == "ServiceAccount" and .name == $name
        and ((.namespace // "") | if . == "" then $bns else . end) == $namespace)
      or (.kind == "User" and .name == "system:serviceaccount:\($namespace):\($name)")
      or (.kind == "Group" and (.name as $group | any($groups[]; . == $group))))
    | "\(.kind) \(if .kind == "ServiceAccount" then "\((.namespace // "") | if . == "" then $bns else . end)/" else "" end)\(.name)")
  // null;

[inputs] as $read
| (if ($namespaces | type) == "array" and ($namespaces | length) > 0 and all($namespaces[]; type == "string")
   then $namespaces else error("no namespaces to read") end) as $asked
# The one list read for WHAT in NS.
| def list($what; $ns):
    [$read[] | select(.what == $what and (.namespace // "") == $ns)]
    | if length == 0 then unreadable("the \($what)\(if $ns == "" then "" else " in \($ns)" end): not given")
      elif length > 1 then unreadable("the \($what)\(if $ns == "" then "" else " in \($ns)" end): given twice")
      else .[0].list | items_of("\($what)\(if $ns == "" then "" else " in \($ns)" end)") end;
  (list("clusterroles"; "") | map({key: name_of("ClusterRoles"), value: rules_of("ClusterRole \(.metadata.name)")}) | from_entries) as $clusterroles
| ([$asked[] as $ns | {key: $ns, value: (list("roles"; $ns)
      | map({key: name_of("Roles in \($ns)"), value: rules_of("Role \($ns)/\(.metadata.name)")}) | from_entries)}]
   | from_entries) as $roles
# Every binding to the ServiceAccount or its groups, with the rules of the role it binds.
| ([(list("clusterrolebindings"; "")[] | {kind: "ClusterRoleBinding", namespace: "", item: .}),
    ($asked[] as $ns | list("rolebindings"; $ns)[] | {kind: "RoleBinding", namespace: $ns, item: .})]
   | map(.kind as $kind | .namespace as $bns
       | (.item | name_of("\($kind)s")) as $bname
       | (if $bns == "" then $bname else "\($bns)/\($bname)" end) as $where
       | (.item | role_ref_of("\($kind) \($where)")) as $ref
       | (.item | subjects_of("\($kind) \($where)") | subject_for($bns)) as $subject
       | select($subject != null)
       | {binding: "\($kind) \($where)", subject: $subject, cluster: ($kind == "ClusterRoleBinding"),
          role: "\($ref.kind) \($ref.name)",
          rules: (if $ref.kind == "ClusterRole" then $clusterroles[$ref.name] // []
                  elif $ref.kind == "Role" and $bns != "" then $roles[$bns][$ref.name] // []
                  else [] end)})) as $bindings
| rows[] as $row
| [$bindings[] | select($row.namespaced or .cluster) | . as $b
   | .rules[] | select(grants($row))
   | "\($b.binding) binds \($b.role) to \($b.subject)"
     + (if .resourceNames == [] then "" else ", for resourceNames \(.resourceNames | join(","))" end)]
  | unique as $granted
| if $granted == [] then
    "PASS\t\($row.label)\t" + (if $row.namespaced then "RoleBindings in \($asked | join(",")), and ClusterRoleBindings" else "ClusterRoleBindings" end)
  else
    "FAIL\t\($row.label)\t\($granted | join("; "))"
  end
