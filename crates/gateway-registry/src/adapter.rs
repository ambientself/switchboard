//! Argument-to-resource adapters (planDemo 14d), and the check of a call's arguments against
//! its tool's approved input schema (decision 0011, section 1).
//!
//! An adapter is declared in the registry file as a list of sources, each
//! `{from_argument, system, kind}`: the named argument's string value is the identifier of a
//! resource of that system and kind. The core's check 6 then compares the resources against
//! the caller's limit. An adapter that cannot find a resource says so by naming none, which
//! check 6 denies for a tool that declares its resources; it never guesses.
//!
//! # The argument check
//!
//! An approved schema is read as JSON Schema 2020-12, and only a subset of it is approved.
//! The loader refuses a schema that uses anything else, so no keyword is accepted and then
//! left unchecked. Decision 0011 lets a schema in another dialect be refused or converted at
//! approval; this loader refuses it, and converts nothing.
//!
//! - **Enforced:** `type` (a name or a list of names; `integer` is a number with no fractional
//!   part, so `1.0` is an integer), `properties`, `required`, `additionalProperties` (`true`,
//!   `false` or a schema), `items` (one schema, or `true` or `false`; the list form is
//!   draft-07's and is refused), `enum`, `const`, `minLength` and `maxLength` (counted in
//!   Unicode code points), `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`
//!   (numbers, as in 2020-12, not draft-04's booleans), `minItems` and `maxItems`.
//! - **Accepted and ignored, as annotations:** `title`, `description`, `default`, `examples`,
//!   `deprecated`, `readOnly`, `writeOnly`, `$comment` and `format`. A format is not checked.
//! - **`$schema`:** at the root only, and only `https://json-schema.org/draft/2020-12/schema`.
//! - **Refused at load:** every other keyword. That includes `pattern`, which is not enforced;
//!   `$ref`, `$id`, `$defs` and `$anchor`, which are not followed; the composition and
//!   conditional keywords (`allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`, `else`,
//!   `dependentSchemas`); `patternProperties`, `unevaluatedProperties`, `prefixItems`; and the
//!   forms valid only in earlier drafts (`definitions`, `dependencies`, `additionalItems`).
//!   An enforced keyword whose value does not have the JSON type 2020-12 gives it is refused
//!   too: `type` must be a type name or a list of them, `required` a list of strings,
//!   `properties` an object of schemas, `enum` a list, a length or count bound a non-negative
//!   integer, and a number bound a number. An `additionalProperties` that is neither a boolean
//!   nor a schema has an error of its own, and so does a `type` list or a `required` list that
//!   names one name twice: 2020-12 says those names must be unique (#127).
//! - **Not checked at load:** an annotation's value, which nothing reads.
//!
//! A call's arguments then pass only if they meet every enforced keyword, at every depth:
//!
//! - The arguments are a JSON object.
//! - Where a schema lists its `properties`, any other property is refused, whatever the schema
//!   says about `additionalProperties`. Such a property is undeclared, not invalid.
//! - Where it lists none, `additionalProperties: false` declares no property, so any property
//!   is undeclared; a schema there is checked against every property's value; `true`, or no
//!   `additionalProperties`, leaves the object open, and it is accepted as one value.
//! - Array elements are checked against `items`; with no `items` they are not checked.
//! - The schema `true` admits anything, and `false` admits nothing, wherever it appears.
//! - Numbers are compared by their mathematical value, as 2020-12 does: `1` and `1.0` are
//!   equal in `enum` and `const` and against a bound.
//! - A keyword that applies to one kind of value, such as `minLength`, is met by a value of
//!   any other kind, as in 2020-12; `type` is what limits the kind.
//!
//! The first failure found is reported: an undeclared property as
//! [`ArgumentError::Undeclared`], any other as [`ArgumentError::Invalid`] with the keyword
//! it failed (`false` for the schema `false`). Within a schema, `type`, `enum` and `const`
//! are checked first, then the bounds for the value's kind. In an object, every property is
//! looked up before any value is checked, so an undeclared property is reported before a
//! declared one's failure; then the values, in key order; then `required`. In an array, the
//! item counts come before the items.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::fmt;

use gateway_core::{Resource, ResourceDeclaration, Resources, ToolName};
use serde_json::{Map, Number, Value};
use thiserror::Error;

/// One resource a tool's calls name: the string argument it is read from, and the system and
/// kind of the resource that string identifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceSource {
    /// The top-level argument that holds the identifier, such as `project`.
    pub from_argument: String,
    /// The resource's system, such as `docs`.
    pub system: String,
    /// The resource's kind within the system, such as `project`.
    pub kind: String,
}

/// One tool's adapter: what the gateway runs on a call's arguments before deciding, and before
/// forwarding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgumentAdapter {
    tool: ToolName,
    sources: Vec<ResourceSource>,
    input_schema: Value,
}

/// Why a call's arguments were refused before forwarding.
///
/// The path is the caller's own text. It is for logs; a sentence shown to a caller should
/// name the tool, not echo the path.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ArgumentError {
    /// The arguments are not a JSON object.
    #[error("the arguments to `{tool}` are not an object")]
    NotAnObject {
        /// The tool called.
        tool: ToolName,
    },
    /// The arguments carry a property the approved schema does not list.
    #[error("the arguments to `{tool}` carry `{path}`, which its approved schema does not declare")]
    Undeclared {
        /// The tool called.
        tool: ToolName,
        /// Where the property is, as a JSON Pointer such as `/options/extra`.
        path: JsonPointer,
    },
    /// A value in the arguments fails a keyword of the approved schema.
    #[error("the arguments to `{tool}` fail `{keyword}` of its approved schema at `{path}`")]
    Invalid {
        /// The tool called.
        tool: ToolName,
        /// Where the value is, as a JSON Pointer; empty for the arguments as a whole.
        path: JsonPointer,
        /// The keyword it fails, such as `type` or `required`, or `false` for the schema
        /// `false`.
        keyword: &'static str,
    },
}

/// A JSON Pointer (RFC 6901) into a call's arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JsonPointer(String);

impl JsonPointer {
    fn child(&self, token: &str) -> Self {
        Self(format!(
            "{}/{}",
            self.0,
            token.replace('~', "~0").replace('/', "~1")
        ))
    }

    /// The pointer as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl ArgumentAdapter {
    pub(crate) fn new(tool: ToolName, sources: Vec<ResourceSource>, input_schema: Value) -> Self {
        Self {
            tool,
            sources,
            input_schema,
        }
    }

    /// The tool this adapter serves.
    pub fn tool(&self) -> &ToolName {
        &self.tool
    }

    /// Where the resources come from. Empty for a tool that names no resources.
    pub fn sources(&self) -> &[ResourceSource] {
        &self.sources
    }

    /// What the approved tool says about its resources: `declared` when the adapter reads
    /// them from the arguments, `no_resources` otherwise. A registry tool is never
    /// `checks_own_scope`: a proxied server is not trusted to check its own scope.
    pub fn declaration(&self) -> ResourceDeclaration {
        if self.sources.is_empty() {
            ResourceDeclaration::NoResources
        } else {
            ResourceDeclaration::Declared
        }
    }

    /// The resources a call with these arguments names, for the call context's `resources`.
    ///
    /// One resource per source, in the order the file lists them. If any source's argument is
    /// missing, is not a string, or is the empty string, the call names no resources at all:
    /// `Named([])`, which check 6 denies for a `declared` tool. Returning the others would let
    /// a call through with one of its targets unchecked. A tool with no sources always names
    /// none. The result is never `Unknown`: the adapter reads the arguments, so it knows.
    pub fn resources(&self, arguments: &Map<String, Value>) -> Resources {
        let mut named = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            match arguments.get(&source.from_argument) {
                Some(Value::String(identifier)) if !identifier.is_empty() => {
                    named.push(Resource {
                        system: source.system.clone(),
                        kind: source.kind.clone(),
                        identifier: identifier.clone(),
                    });
                }
                _ => return Resources::Named(Vec::new()),
            }
        }
        Resources::Named(named)
    }

    /// Checks a call's arguments against the approved schema, read as JSON Schema 2020-12,
    /// before the call is forwarded.
    ///
    /// The arguments must be an object and meet every keyword the loader accepted, at every
    /// depth. Where a schema lists `properties`, any other property is undeclared. The schema
    /// `false` admits nothing, and numbers compare by value. The full rules, and the subset of
    /// 2020-12 the loader accepts, are in the documentation at the top of `adapter.rs`.
    pub fn check_arguments(&self, arguments: &Value) -> Result<(), ArgumentError> {
        if !arguments.is_object() {
            return Err(ArgumentError::NotAnObject {
                tool: self.tool.clone(),
            });
        }
        validate(&self.input_schema, arguments, &JsonPointer::default()).map_err(|failure| {
            match failure {
                Failure::Undeclared(path) => ArgumentError::Undeclared {
                    tool: self.tool.clone(),
                    path,
                },
                Failure::Invalid(path, keyword) => ArgumentError::Invalid {
                    tool: self.tool.clone(),
                    path,
                    keyword,
                },
            }
        })
    }
}

/// The first way a value fails a schema.
enum Failure {
    Undeclared(JsonPointer),
    Invalid(JsonPointer, &'static str),
}

fn invalid(at: &JsonPointer, keyword: &'static str) -> Failure {
    Failure::Invalid(at.clone(), keyword)
}

/// Whether a value's comparison with a bound meets the bound.
type Meets = fn(Ordering) -> bool;

/// The bounds on a number, each with the comparisons of the value against it that meet it.
const NUMBER_BOUNDS: [(&str, Meets); 4] = [
    ("minimum", Ordering::is_ge),
    ("maximum", Ordering::is_le),
    ("exclusiveMinimum", Ordering::is_gt),
    ("exclusiveMaximum", Ordering::is_lt),
];

/// Checks `value`, found at `at`, against `schema`. The loader has refused every schema this
/// cannot check fully.
fn validate(schema: &Value, value: &Value, at: &JsonPointer) -> Result<(), Failure> {
    let Value::Object(schema) = schema else {
        // `true` admits anything; `false`, and anything the loader would have refused, nothing.
        return if *schema == Value::Bool(true) {
            Ok(())
        } else {
            Err(invalid(at, "false"))
        };
    };
    if let Some(types) = schema.get("type")
        && !has_type(types, value)
    {
        return Err(invalid(at, "type"));
    }
    if let Some(Value::Array(allowed)) = schema.get("enum")
        && !allowed.iter().any(|allowed| same(allowed, value))
    {
        return Err(invalid(at, "enum"));
    }
    if let Some(constant) = schema.get("const")
        && !same(constant, value)
    {
        return Err(invalid(at, "const"));
    }
    match value {
        Value::String(text) => {
            let length = text.chars().count() as u64;
            counted(schema, length, "minLength", "maxLength", at)
        }
        Value::Number(number) => {
            for (keyword, meets) in NUMBER_BOUNDS {
                if let Some(bound) = schema.get(keyword).and_then(Value::as_number)
                    && !meets(compare(number, bound))
                {
                    return Err(invalid(at, keyword));
                }
            }
            Ok(())
        }
        Value::Array(items) => {
            counted(schema, items.len() as u64, "minItems", "maxItems", at)?;
            let Some(each) = schema.get("items") else {
                return Ok(());
            };
            items
                .iter()
                .enumerate()
                .try_for_each(|(index, item)| validate(each, item, &at.child(&index.to_string())))
        }
        Value::Object(object) => {
            match schema.get("properties").and_then(Value::as_object) {
                Some(properties) => {
                    if let Some(key) = object.keys().find(|key| !properties.contains_key(*key)) {
                        return Err(Failure::Undeclared(at.child(key)));
                    }
                    for (key, value) in object {
                        if let Some(property) = properties.get(key) {
                            validate(property, value, &at.child(key))?;
                        }
                    }
                }
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => {
                        if let Some(key) = object.keys().next() {
                            return Err(Failure::Undeclared(at.child(key)));
                        }
                    }
                    Some(additional) => {
                        for (key, value) in object {
                            validate(additional, value, &at.child(key))?;
                        }
                    }
                    None => {}
                },
            }
            if let Some(Value::Array(required)) = schema.get("required")
                && required
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|name| !object.contains_key(name))
            {
                return Err(invalid(at, "required"));
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) => Ok(()),
    }
}

/// Checks a length or a count against the schema's lower and upper bounds for it.
fn counted(
    schema: &Map<String, Value>,
    count: u64,
    lower: &'static str,
    upper: &'static str,
    at: &JsonPointer,
) -> Result<(), Failure> {
    if schema
        .get(lower)
        .and_then(non_negative_integer)
        .is_some_and(|least| count < least)
    {
        return Err(invalid(at, lower));
    }
    if schema
        .get(upper)
        .and_then(non_negative_integer)
        .is_some_and(|most| count > most)
    {
        return Err(invalid(at, upper));
    }
    Ok(())
}

/// Whether `value` is of the type, or one of the types, `types` names.
fn has_type(types: &Value, value: &Value) -> bool {
    match types {
        Value::String(name) => is_of(name, value),
        Value::Array(names) => names
            .iter()
            .filter_map(Value::as_str)
            .any(|name| is_of(name, value)),
        _ => false,
    }
}

fn is_of(name: &str, value: &Value) -> bool {
    match (name, value) {
        ("null", Value::Null)
        | ("boolean", Value::Bool(_))
        | ("object", Value::Object(_))
        | ("array", Value::Array(_))
        | ("string", Value::String(_))
        | ("number", Value::Number(_)) => true,
        ("integer", Value::Number(number)) => is_integer(number),
        _ => false,
    }
}

/// Whether a number has no fractional part, however it is written: `1.0` is an integer.
fn is_integer(number: &Number) -> bool {
    integer(number).is_some() || number.as_f64().is_some_and(|float| float.fract() == 0.0)
}

/// A number held as an integer, exactly.
fn integer(number: &Number) -> Option<i128> {
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

/// A number as a float. JSON has no NaN or infinity, so every number has one.
fn float(number: &Number) -> f64 {
    number.as_f64().unwrap_or(f64::NAN)
}

/// Compares two numbers by their mathematical value, without rounding an integer to a float.
fn compare(a: &Number, b: &Number) -> Ordering {
    match (integer(a), integer(b)) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(a), None) => integer_against_float(a, float(b)),
        (None, Some(b)) => integer_against_float(b, float(a)).reverse(),
        (None, None) => float(a).partial_cmp(&float(b)).unwrap_or(Ordering::Equal),
    }
}

/// Compares an integer held exactly (an `i64` or a `u64`) with a float, exactly.
fn integer_against_float(integer: i128, float: f64) -> Ordering {
    // Past these, the float is beyond every i64 and u64, and its floor would not fit.
    const ABOVE_U64: f64 = 18_446_744_073_709_551_616.0;
    const BELOW_I64: f64 = -9_223_372_036_854_775_808.0;
    let floor = float.floor();
    if floor >= ABOVE_U64 {
        return Ordering::Less;
    }
    if floor < BELOW_I64 {
        return Ordering::Greater;
    }
    // In range and with no fractional part, so the conversion is exact.
    let floor_integer = floor as i128;
    match integer.cmp(&floor_integer) {
        Ordering::Equal if float > floor => Ordering::Less,
        other => other,
    }
}

/// Whether two values are equal as 2020-12 says: numbers by mathematical value, at any depth.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => compare(a, b) == Ordering::Equal,
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| same(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| same(a, b)))
        }
        _ => a == b,
    }
}

/// A non-negative integer, as a count or a length is given: `2` or `2.0`.
fn non_negative_integer(value: &Value) -> Option<u64> {
    let number = value.as_number()?;
    number.as_u64().or_else(|| {
        number
            .as_f64()
            .filter(|float| *float >= 0.0 && float.fract() == 0.0)
            // Saturates past u64::MAX, which no count reaches.
            .map(|float| float as u64)
    })
}

/// The only dialect `$schema` may name.
pub(crate) const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Keywords accepted and ignored: annotations, which say nothing about what is valid.
pub(crate) const ANNOTATIONS: [&str; 9] = [
    "title",
    "description",
    "default",
    "examples",
    "deprecated",
    "readOnly",
    "writeOnly",
    "$comment",
    "format",
];

/// The names `type` may give.
const TYPE_NAMES: [&str; 7] = [
    "null", "boolean", "object", "array", "number", "string", "integer",
];

/// Why a schema cannot be approved, and where. Pointers are into the schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SchemaProblem {
    /// A keyword outside the approved subset, in the schema at `at`.
    Unfollowed { keyword: String, at: JsonPointer },
    /// An enforced keyword whose value does not have the JSON type 2020-12 gives it, or a
    /// subschema that is not a schema; `at` is the value.
    Malformed { at: JsonPointer },
    /// `$schema` at the root names a dialect other than 2020-12: the value, as written.
    Dialect { dialect: String },
    /// An `additionalProperties` that is neither a boolean nor a schema.
    AdditionalProperties { at: JsonPointer },
    /// A `type` or `required` list, at `at`, that names `name` more than once.
    Repeated { name: String, at: JsonPointer },
}

/// Checks that `schema`, found at `at`, uses only the approved subset of 2020-12, each enforced
/// keyword with a value of the JSON type 2020-12 gives it, and that so does every schema inside
/// it, and that no `type` or `required` list names a name twice. Annotation values are not
/// checked.
pub(crate) fn followable(schema: &Value, at: &JsonPointer) -> Result<(), SchemaProblem> {
    let object = match schema {
        Value::Bool(_) => return Ok(()),
        Value::Object(object) => object,
        _ => return Err(SchemaProblem::Malformed { at: at.clone() }),
    };
    for (keyword, value) in object {
        let here = at.child(keyword);
        let formed = match keyword.as_str() {
            "type" => names_types(value) && unique(value, &here)?,
            "properties" => {
                let Some(properties) = value.as_object() else {
                    return Err(SchemaProblem::Malformed { at: here });
                };
                for (name, property) in properties {
                    followable(property, &here.child(name))?;
                }
                true
            }
            "required" => {
                value
                    .as_array()
                    .is_some_and(|names| names.iter().all(Value::is_string))
                    && unique(value, &here)?
            }
            "additionalProperties" => {
                if !(value.is_boolean() || value.is_object()) {
                    return Err(SchemaProblem::AdditionalProperties { at: here });
                }
                followable(value, &here)?;
                true
            }
            "items" => {
                followable(value, &here)?;
                true
            }
            "enum" => value.is_array(),
            "const" => true,
            "minLength" | "maxLength" | "minItems" | "maxItems" => {
                non_negative_integer(value).is_some()
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => value.is_number(),
            "$schema" if at.as_str().is_empty() => {
                if value.as_str() != Some(DIALECT) {
                    return Err(SchemaProblem::Dialect {
                        dialect: value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned),
                    });
                }
                true
            }
            annotation if ANNOTATIONS.contains(&annotation) => true,
            _ => {
                return Err(SchemaProblem::Unfollowed {
                    keyword: keyword.clone(),
                    at: at.clone(),
                });
            }
        };
        if !formed {
            return Err(SchemaProblem::Malformed { at: here });
        }
    }
    Ok(())
}

/// Checks that a list of names, the value of `type` or `required` at `at`, names none twice, as
/// 2020-12 requires. A single name is unique. Returns `true`, so that it reads as part of the
/// keyword's form.
fn unique(value: &Value, at: &JsonPointer) -> Result<bool, SchemaProblem> {
    let mut seen = HashSet::new();
    for name in value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !seen.insert(name) {
            return Err(SchemaProblem::Repeated {
                name: name.to_owned(),
                at: at.clone(),
            });
        }
    }
    Ok(true)
}

/// Whether a `type` value is a type name or a list of them.
fn names_types(value: &Value) -> bool {
    let named = |name: &Value| name.as_str().is_some_and(|name| TYPE_NAMES.contains(&name));
    match value {
        Value::String(_) => named(value),
        Value::Array(names) => names.iter().all(named),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_pointer_escapes_its_tokens() {
        let at = JsonPointer::default().child("a/b").child("c~d");
        assert_eq!(at.as_str(), "/a~1b/c~0d");
    }

    #[test]
    fn numbers_compare_by_value_however_they_are_held() {
        let number = |value: Value| match value {
            Value::Number(number) => number,
            other => panic!("{other} is not a number"),
        };
        let cases = [
            (json!(1), json!(1.0), Ordering::Equal),
            (json!(1), json!(1.5), Ordering::Less),
            (json!(2), json!(1.5), Ordering::Greater),
            (json!(-1), json!(-1.5), Ordering::Greater),
            (json!(-2), json!(-1.5), Ordering::Less),
            (json!(u64::MAX), json!(1.0e30), Ordering::Less),
            (json!(i64::MIN), json!(-1.0e30), Ordering::Greater),
            // 2^53 + 1 is not a float; as one it would round to 2^53 and compare equal.
            (
                json!(9_007_199_254_740_993_u64),
                json!(9_007_199_254_740_992.0),
                Ordering::Greater,
            ),
            (json!(u64::MAX), json!(-1), Ordering::Greater),
            (json!(0.5), json!(0.25), Ordering::Greater),
        ];
        for (a, b, want) in cases {
            assert_eq!(
                compare(&number(a.clone()), &number(b.clone())),
                want,
                "{a} {b}"
            );
            assert_eq!(
                compare(&number(b.clone()), &number(a.clone())),
                want.reverse(),
                "{b} {a}"
            );
        }
    }
}
