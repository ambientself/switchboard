//! Reading the request headers the adapter checks.

use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use http::HeaderMap;
use http::header::{ACCEPT, CONTENT_TYPE};

/// A header that should appear at most once.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Single<'a> {
    Absent,
    One(&'a str),
    /// Sent more than once, or with bytes outside visible ASCII, space and tab.
    Malformed,
}

pub(crate) fn single<'a>(headers: &'a HeaderMap, name: &str) -> Single<'a> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Single::Absent;
    };
    if values.next().is_some() {
        return Single::Malformed;
    }
    match first.to_str() {
        Ok(value) => Single::One(value),
        Err(_) => Single::Malformed,
    }
}

/// True when the one `Content-Type` is `application/json`, with at most a UTF-8 charset.
pub(crate) fn content_type_is_json(headers: &HeaderMap) -> bool {
    let Single::One(value) = single(headers, CONTENT_TYPE.as_str()) else {
        return false;
    };
    let mut parts = value.split(';');
    let media_type = parts.next().unwrap_or_default().trim();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return false;
    }
    parts.all(|parameter| {
        let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
        !name.trim().eq_ignore_ascii_case("charset")
            || value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
    })
}

/// True when there is no `Accept` header, or one of its media ranges admits
/// `application/json` with a quality above zero.
pub(crate) fn accept_admits_json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(ACCEPT).iter().peekable();
    if values.peek().is_none() {
        return true;
    }
    values.any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.split(',').any(range_admits_json))
    })
}

fn range_admits_json(range: &str) -> bool {
    let mut parts = range.split(';');
    let media_range = parts.next().unwrap_or_default().trim();
    let matches = ["application/json", "application/*", "*/*"]
        .iter()
        .any(|accepted| media_range.eq_ignore_ascii_case(accepted));
    let refused = parts.any(|parameter| {
        parameter.split_once('=').is_some_and(|(name, quality)| {
            name.trim().eq_ignore_ascii_case("q")
                && quality.trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
        })
    });
    matches && !refused
}

const SENTINEL_PREFIX: &str = "=?base64?";
const SENTINEL_SUFFIX: &str = "?=";

/// Padding is accepted with or without, as encoders differ.
const SENTINEL_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// The value an `Mcp-Name` header stands for. A value in the `=?base64?...?=` sentinel form is
/// decoded, and must decode to UTF-8; any other value stands for itself. The markers are
/// case-sensitive.
pub(crate) fn header_name_value(value: &str) -> Option<String> {
    match value
        .strip_prefix(SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(SENTINEL_SUFFIX))
    {
        Some(encoded) => {
            let bytes = SENTINEL_ENGINE.decode(encoded).ok()?;
            String::from_utf8(bytes).ok()
        }
        None => Some(value.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use base64::engine::general_purpose;

    fn encode(value: &str) -> String {
        format!("=?base64?{}?=", general_purpose::STANDARD.encode(value))
    }

    #[test]
    fn a_sentinel_decodes_and_a_plain_value_stands_for_itself() {
        assert_eq!(header_name_value("read_document").unwrap(), "read_document");
        assert_eq!(
            header_name_value(&encode("Hello, 世界")).unwrap(),
            "Hello, 世界"
        );
        assert_eq!(
            header_name_value(&encode("=?base64?literal?=")).unwrap(),
            "=?base64?literal?="
        );
        assert_eq!(header_name_value("=?base64?SGk?=").unwrap(), "Hi");
    }

    #[test]
    fn a_sentinel_that_does_not_decode_stands_for_nothing() {
        assert_eq!(header_name_value("=?base64?not base64!?="), None);
        assert_eq!(header_name_value("=?base64?/w==?="), None);
    }

    #[test]
    fn the_markers_are_case_sensitive() {
        assert_eq!(
            header_name_value("=?BASE64?SGk?=").unwrap(),
            "=?BASE64?SGk?="
        );
    }

    #[test]
    fn accept_ranges_with_quality_zero_do_not_admit() {
        let admits = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(ACCEPT, value.parse().unwrap());
            accept_admits_json(&headers)
        };
        assert!(admits("application/json, text/event-stream"));
        assert!(admits("text/event-stream, */*;q=0.1"));
        assert!(admits("Application/*"));
        assert!(!admits("text/event-stream"));
        assert!(!admits("application/json;q=0"));
        assert!(!admits("application/json; q=0.0, text/html"));
        assert!(!admits("application/jsonl"));
        assert!(accept_admits_json(&HeaderMap::new()));
    }

    #[test]
    fn content_type_takes_a_utf8_charset_only() {
        let json = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, value.parse().unwrap());
            content_type_is_json(&headers)
        };
        assert!(json("application/json"));
        assert!(json("Application/JSON; charset=utf-8"));
        assert!(json("application/json; charset=\"UTF-8\""));
        assert!(!json("application/json; charset=latin1"));
        assert!(!json("application/json-rpc"));
        assert!(!json("text/plain"));
        assert!(!content_type_is_json(&HeaderMap::new()));
    }
}
