//! Reach reports (decision 0011, section 4): a reach-report entry, held to its one job, and an
//! entry whose reach is checked against the report its tool reads. What loads, and one case per
//! way either can be wrong.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use gateway_core::{ConnectorName, ToolName};
use gateway_registry::{
    REACH_SURFACE, ReachReport, Registry, RegistryError, StatedResources,
    built_in_binding_sha256, definition_sha256,
};

const REPORT_TOOL: &str = "github__list_installation_repositories";
const READ_TOOL: &str = "github__get_file";

/// What a case changes from the registry that loads.
struct Case {
    /// The checked entry's fields after its tools.
    checked: &'static str,
    /// The reach-report entry's fields after its tools.
    report: &'static str,
    /// The report tool's classification.
    classification: &'static str,
    /// The name of the surface that serves the report tool.
    surface: &'static str,
    /// The `principals` of the surface that serves the report tool.
    principals: &'static str,
    /// How the checked entry's tool's resources are known.
    read_resources: &'static str,
    /// Whether the report tool is approved.
    report_approved: bool,
    /// Whether the checked entry's tool is approved.
    read_approved: bool,
}

const CHECKED: &str = r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "limit"
permits = "read"
reach = [
  { system = "github", kind = "repository", identifier = "example-org/atlas" },
  { system = "github", kind = "repository", identifier = "example-org/borealis" },
]
reach_report = { tool = "github__list_installation_repositories" }"#;

const REPORT: &str = r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "none"
permits = "read"
reports_reach = true"#;

const ONLY: &str = r#"{ only = [{ issuer = "https://workloads.example.test", subject = "system:serviceaccount:switchboard:registry" }] }"#;

/// The registry's identity and one more named principal.
const TWO: &str = r#"{ only = [{ issuer = "https://workloads.example.test", subject = "system:serviceaccount:switchboard:registry" }, { issuer = "https://workloads.example.test", subject = "system:serviceaccount:team-a:agent" }] }"#;

const FROM_ARGUMENTS: &str = r#"{ from_arguments = [{ from_argument = "repo", system = "github", kind = "repository" }] }"#;

impl Default for Case {
    fn default() -> Self {
        Self {
            checked: CHECKED,
            report: REPORT,
            classification: "read",
            surface: REACH_SURFACE,
            principals: ONLY,
            read_resources: FROM_ARGUMENTS,
            report_approved: true,
            read_approved: true,
        }
    }
}

fn name(text: &str) -> ConnectorName {
    ConnectorName::new(text)
}

fn tool(text: &str) -> ToolName {
    ToolName::parse(text).unwrap()
}

/// The entries and surfaces of `case`, with no approvals. The surfaces serve the approved tools
/// when `served`, and nothing otherwise, so the entries alone can load to be hashed.
fn head(case: &Case, served: bool) -> String {
    let tools = |approved: bool, name: &str| {
        if served && approved {
            format!(r#"["{name}"]"#)
        } else {
            "[]".to_owned()
        }
    };
    format!(
        r#"revision = "r1"
servers = []
tools = []
profiles = []
profile_rules = []

[[connectors]]
name = "github-read"
system = "github"
permissions = {{ contents = "read" }}
tools = ["{READ_TOOL}"]
{checked}

[[connectors]]
name = "github-reach-report"
system = "github"
permissions = {{ metadata = "read" }}
tools = ["{REPORT_TOOL}"]
{report}

[[surfaces]]
name = "github"
tools = {read_surface}
teams = ["team-a"]
principals = "any_in_teams_and_groups"

[[surfaces]]
name = "{surface}"
tools = {report_surface}
teams = ["registry"]
principals = {principals}

[limits.teams]
team-a = [
  {{ system = "github", kind = "repository", identifier = "example-org/atlas" }},
  {{ system = "github", kind = "repository", identifier = "example-org/borealis" }},
]
registry = []
"#,
        checked = case.checked,
        report = case.report,
        surface = case.surface,
        principals = case.principals,
        read_surface = tools(case.read_approved, READ_TOOL),
        report_surface = tools(case.report_approved, REPORT_TOOL),
    )
}

/// One approval of `tool` on `connector`, with `schema` (in TOML and in JSON), its binding
/// hashed from `entries`, the registry of the entries alone, if that loads.
fn approval(
    entries: Option<&Registry>,
    tool: &str,
    connector: &str,
    classification: &str,
    schema: (&str, serde_json::Value),
    resources: &str,
) -> String {
    let (schema, json) = schema;
    let definition = definition_sha256(tool, None, "Reads.", &json);
    let binding = entries
        .and_then(|registry| built_in_binding_sha256(&registry.connectors()[&name(connector)]))
        .unwrap_or_default();
    // A tool not classified `read` must say how its receipts are settled.
    let settlement = if classification == "read" {
        ""
    } else {
        "settlement = \"person\"\n"
    };
    format!(
        r#"
[[built_in_tools]]
name = "{tool}"
connector = "{connector}"
classification = "{classification}"
description = "Reads."
input_schema = {schema}
approved_by = "reviewer"
approved_at = 2026-10-15T00:00:00Z
definition_sha256 = "{definition}"
binding_sha256 = "{binding}"
resources = {resources}
{settlement}"#
    )
}

/// The registry file of `case`.
fn text(case: &Case) -> String {
    let entries = Registry::from_toml_str(&head(case, false)).ok();
    let mut text = head(case, true);
    if case.read_approved {
        text.push_str(&approval(
            entries.as_ref(),
            READ_TOOL,
            "github-read",
            "read",
            (
                r#"{ type = "object", additionalProperties = false, properties = { repo = { type = "string" } } }"#,
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {"repo": {"type": "string"}},
                }),
            ),
            case.read_resources,
        ));
    }
    if case.report_approved {
        text.push_str(&approval(
            entries.as_ref(),
            REPORT_TOOL,
            "github-reach-report",
            case.classification,
            (
                r#"{ type = "object", additionalProperties = false, properties = {} }"#,
                serde_json::json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {},
                }),
            ),
            r#""no_resources""#,
        ));
    }
    text
}

fn load(case: &Case) -> Result<Registry, RegistryError> {
    Registry::from_toml_str(&text(case))
}

#[test]
fn a_reach_report_and_the_entry_it_checks_load() {
    let registry = load(&Case::default()).unwrap();
    let checked = &registry.connectors()[&name("github-read")];
    assert_eq!(
        checked.reach_report,
        Some(ReachReport {
            tool: tool(REPORT_TOOL)
        })
    );
    assert!(!checked.reports_reach);
    let report = &registry.connectors()[&name("github-reach-report")];
    assert!(report.reports_reach);
    assert_eq!(report.reach_report, None);
    assert_eq!(
        registry.built_in_tools()[&tool(REPORT_TOOL)],
        name("github-reach-report")
    );
}

/// The flag is in the reach-report entry's binding, so flipping it needs its tools approved
/// again; the reach report is not, as a proxied entry's reach check is not.
#[test]
fn the_binding_covers_reports_reach_but_not_the_reach_report() {
    let registry = load(&Case::default()).unwrap();
    let report = &registry.connectors()[&name("github-reach-report")];
    let mut unflagged = report.clone();
    unflagged.reports_reach = false;
    assert_ne!(
        built_in_binding_sha256(report),
        built_in_binding_sha256(&unflagged)
    );
    let checked = &registry.connectors()[&name("github-read")];
    let mut unchecked = checked.clone();
    unchecked.reach_report = None;
    assert_eq!(
        built_in_binding_sha256(checked),
        built_in_binding_sha256(&unchecked)
    );
}

#[test]
fn a_reach_report_entry_not_held_to_its_job_is_refused() {
    let entry = |problem: &str| RegistryError::ReachReportEntry {
        connector: name("github-reach-report"),
        problem: problem.to_owned(),
    };
    let cases: Vec<(&str, Case, RegistryError)> = vec![
        (
            "a reach-report entry that declares no credential",
            Case {
                report: "reports_reach = true",
                report_approved: false,
                ..Case::default()
            },
            entry("declares no credential"),
        ),
        (
            "a reach-report entry narrowed to the limit",
            Case {
                report: r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "limit"
permits = "read"
reports_reach = true"#,
                ..Case::default()
            },
            entry("is not narrowed \"none\", though its credential reads the whole report"),
        ),
        (
            "a reach-report entry that permits writes",
            Case {
                report: r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "none"
permits = "write"
reports_reach = true"#,
                ..Case::default()
            },
            entry("permits more than \"read\""),
        ),
        (
            "a reach-report entry with a reach",
            Case {
                report: r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "none"
permits = "read"
reach = [{ system = "github", kind = "repository", identifier = "example-org/atlas" }]
reports_reach = true"#,
                ..Case::default()
            },
            entry("gives a reach"),
        ),
        (
            "a reach-report entry with a reach report of its own",
            Case {
                report: r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "none"
permits = "read"
reports_reach = true
reach_report = { tool = "github__list_installation_repositories" }"#,
                ..Case::default()
            },
            entry("has a reach report of its own"),
        ),
        (
            "a reach report's tool approved as a write",
            Case {
                classification: "write",
                ..Case::default()
            },
            entry(&format!("approves `{REPORT_TOOL}` as `write`")),
        ),
        (
            "a reach report's tool served to any principal of a team",
            Case {
                principals: r#""any_in_teams_and_groups""#,
                ..Case::default()
            },
            RegistryError::ReachReportSurface {
                surface: "registry-reach".into(),
                tool: tool(REPORT_TOOL),
            },
        ),
        (
            "a reach report's tool served on registry-reach to a second named principal",
            Case {
                principals: TWO,
                ..Case::default()
            },
            RegistryError::ReachReportSurface {
                surface: "registry-reach".into(),
                tool: tool(REPORT_TOOL),
            },
        ),
        (
            "a reach report's tool served on another surface restricted to its one principal",
            Case {
                surface: "reach-elsewhere",
                ..Case::default()
            },
            RegistryError::ReachReportSurface {
                surface: "reach-elsewhere".into(),
                tool: tool(REPORT_TOOL),
            },
        ),
    ];
    for (what, case, want) in cases {
        assert_eq!(load(&case).unwrap_err(), want, "{what}");
    }
}

/// The refusal of a reach report's tool on any surface but the registry's own says where it may
/// be served.
#[test]
fn a_reach_reports_tool_is_served_on_registry_reach_alone() {
    let refused = load(&Case {
        surface: "reach-elsewhere",
        ..Case::default()
    })
    .unwrap_err();
    assert_eq!(
        refused.to_string(),
        format!(
            "surface `reach-elsewhere` serves `{REPORT_TOOL}`, a reach report's tool; serve it \
             only on `registry-reach`, restricted to one named principal, the registry's own \
             identity"
        )
    );
}

/// A tool declared as its entry's reach loads on an entry that records one and names its reach
/// report, and its approval states it is declared as the reach.
#[test]
fn a_tool_declared_as_a_checked_reach_loads() {
    let registry = load(&Case {
        read_resources: r#""as_reach""#,
        ..Case::default()
    })
    .unwrap();
    assert_eq!(
        registry.built_in_assurances()[&tool(READ_TOOL)].resources,
        StatedResources::AsReach
    );
    assert_eq!(
        registry.built_in_assurances()[&tool(REPORT_TOOL)].resources,
        StatedResources::NoResources
    );
}

#[test]
fn a_reach_report_that_cannot_check_its_entry_is_refused() {
    let report = |problem: String| RegistryError::ReachReport {
        connector: name("github-read"),
        problem,
    };
    let reach_problem = || {
        "needs a declared reach that is not empty and holds only resources of system `github` \
         and kind `repository`, which is what the report lists"
            .to_owned()
    };
    let cases: Vec<(&str, Case, RegistryError)> = vec![
        (
            "a reach report naming a tool no reach-report entry lists",
            Case {
                checked: r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "limit"
permits = "read"
reach = [{ system = "github", kind = "repository", identifier = "example-org/atlas" }]
reach_report = { tool = "github__get_file" }"#,
                ..Case::default()
            },
            report(
                "names `github__get_file`, which no entry of system `github` with \
                 `reports_reach = true` lists"
                    .to_owned(),
            ),
        ),
        (
            "a reach report on an entry with no reach",
            Case {
                checked: r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "limit"
permits = "read"
reach_report = { tool = "github__list_installation_repositories" }"#,
                ..Case::default()
            },
            report(reach_problem()),
        ),
        (
            "a reach report on an entry whose reach holds another kind",
            Case {
                checked: r#"credential = { mode = "team_service_identity", principal = "app" }
narrowing = "limit"
permits = "read"
reach = [{ system = "github", kind = "organization", identifier = "example-org" }]
reach_report = { tool = "github__list_installation_repositories" }"#,
                ..Case::default()
            },
            report(reach_problem()),
        ),
        (
            "a reach report on an entry that declares no credential",
            Case {
                checked: r#"reach_report = { tool = "github__list_installation_repositories" }"#,
                read_approved: false,
                ..Case::default()
            },
            report(reach_problem()),
        ),
        (
            "a reach report whose tool is not approved while the entry's tools are",
            Case {
                report_approved: false,
                ..Case::default()
            },
            report(format!(
                "names `{REPORT_TOOL}`, which is not approved, and other tools of the entry \
                 are: they would be served under a credential whose reach is never checked"
            )),
        ),
    ];
    for (what, case, want) in cases {
        assert_eq!(load(&case).unwrap_err(), want, "{what}");
    }
    // With none of the entry's tools approved, the report's tool need not be either.
    load(&Case {
        report_approved: false,
        read_approved: false,
        ..Case::default()
    })
    .unwrap();
}
