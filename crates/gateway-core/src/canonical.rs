//! Canonical JSON, for the argument digest of a receipt (decision 0009, "The argument digest").
//!
//! The form is RFC 8785's, the JSON Canonicalization Scheme, with one change the decision
//! makes: an integer is written exactly, as its decimal digits, rather than as the double
//! nearest to it, so two different large integers never share a form.
//!
//! - No whitespace anywhere.
//! - An object's members are sorted by their names, compared as sequences of UTF-16 code
//!   units, as RFC 8785 says. That is not the order of the names' UTF-8 bytes, which is the
//!   order `serde_json`'s map keeps: a name holding a character past U+FFFF sorts before one
//!   holding a character from U+E000 to U+FFFF in UTF-16, and after it in UTF-8.
//! - A string is written with `"` and `\` escaped as `\"` and `\\`, U+0008, U+0009, U+000A,
//!   U+000C and U+000D as `\b`, `\t`, `\n`, `\f` and `\r`, every other character below U+0020
//!   as `\u` and four lowercase hex digits, and every other character as itself, in UTF-8.
//! - An integer, held by `serde_json` as a 64-bit signed or unsigned integer, is written as its
//!   decimal digits, with a `-` if it is negative.
//! - Any other number, a double, is written as ECMAScript's `Number.prototype.toString` writes
//!   it, which RFC 8785 requires: the shortest digits that read back as the same double, in
//!   plain notation from 10^-6 up to below 10^21 and in exponent notation, `1e+21`, outside it.
//!   Negative zero is written `0`.
//!
//! What the core is given is a [`serde_json::Value`] the gateway parsed, and `serde_json` in
//! this workspace is built without its `arbitrary_precision` feature. So an integer that does
//! not fit in 64 bits reaches the core already read as the nearest double, and two such
//! integers that are nearest the same double have one digest. Within the range of `i64` and
//! `u64` every integer is held, and written, exactly.

use std::cmp::Ordering;
use std::fmt::Write as _;

use serde_json::{Number, Value};

/// `value` in canonical form.
pub(crate) fn canonical(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(number, out),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (position, item) in items.iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut sorted: Vec<(&String, &Value)> = members.iter().collect();
            sorted.sort_by(|(one, _), (other, _)| utf16_order(one, other));
            out.push('{');
            for (position, (name, member)) in sorted.into_iter().enumerate() {
                if position > 0 {
                    out.push(',');
                }
                write_string(name, out);
                out.push(':');
                write_value(member, out);
            }
            out.push('}');
        }
    }
}

/// The order RFC 8785 sorts member names in: by UTF-16 code units.
fn utf16_order(one: &str, other: &str) -> Ordering {
    one.encode_utf16().cmp(other.encode_utf16())
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(number: &Number, out: &mut String) {
    if let Some(unsigned) = number.as_u64() {
        let _ = write!(out, "{unsigned}");
    } else if let Some(signed) = number.as_i64() {
        let _ = write!(out, "{signed}");
    } else if let Some(double) = number.as_f64() {
        write_double(double, out);
    }
}

/// `double` as ECMAScript's `Number.prototype.toString` writes it. `serde_json` holds no NaN
/// or infinity, so `double` is finite.
fn write_double(double: f64, out: &mut String) {
    if double == 0.0 {
        out.push('0');
        return;
    }
    if double < 0.0 {
        out.push('-');
    }
    let (digits, exponent) = shortest_digits(double.abs());
    // In ECMAScript's terms: the value is 0.digits times 10^n, with k digits.
    let k = i32::try_from(digits.len()).unwrap_or(i32::MAX);
    let n = exponent + 1;
    if k <= n && n <= 21 {
        out.push_str(&digits);
        out.extend(std::iter::repeat_n(
            '0',
            usize::try_from(n - k).unwrap_or(0),
        ));
    } else if 0 < n && n <= 21 {
        let (whole, fraction) = digits.split_at(usize::try_from(n).unwrap_or(0));
        out.push_str(whole);
        out.push('.');
        out.push_str(fraction);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', usize::try_from(-n).unwrap_or(0)));
        out.push_str(&digits);
    } else {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        let shown = n - 1;
        let _ = write!(out, "e{}{}", if shown < 0 { '-' } else { '+' }, shown.abs());
    }
}

/// The digits ECMAScript writes for `double`, a positive finite double, and the exponent of the
/// first: the fewest digits that read back as `double`, and of those the nearest to it.
///
/// Rust's `{:e}` gives the fewest digits, the nearest of them. Where two are equally near,
/// ECMAScript takes the one whose last digit is even, and Rust may take the other, so that
/// case is settled here from the double's exact value, which `{:.766e}` writes in full: no
/// double has more than 767 significant digits.
fn shortest_digits(double: f64) -> (String, i32) {
    let (digits, exponent) = split_scientific(&format!("{double:e}"));
    let (exact, exact_exponent) = split_scientific(&format!("{double:.766e}"));
    if exact_exponent != exponent || exact.len() <= digits.len() {
        return (digits, exponent);
    }
    let (head, tail) = exact.split_at(digits.len());
    let halfway = tail
        .strip_prefix('5')
        .is_some_and(|rest| rest.bytes().all(|b| b == b'0'));
    if !halfway {
        return (digits, exponent);
    }
    // Exactly halfway between `head` and the number one above it in its last digit.
    let even = [Some(head.to_owned()), one_above(head)]
        .into_iter()
        .flatten()
        .find(|candidate| candidate.bytes().last().is_some_and(|last| last % 2 == 0));
    match even {
        Some(even) if reads_back(&even, exponent) == Some(double) => (even, exponent),
        _ => (digits, exponent),
    }
}

/// The digits and exponent of Rust's `d.ddde<exponent>`.
fn split_scientific(scientific: &str) -> (String, i32) {
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((scientific, "0"));
    let digits = mantissa.chars().filter(char::is_ascii_digit).collect();
    (digits, exponent.parse().unwrap_or(0))
}

/// `digits` as a number one greater in its last digit, with as many digits, or `None` if that
/// carries into a new first digit.
fn one_above(digits: &str) -> Option<String> {
    let mut bytes = digits.as_bytes().to_vec();
    for byte in bytes.iter_mut().rev() {
        if *byte == b'9' {
            *byte = b'0';
        } else {
            *byte += 1;
            return String::from_utf8(bytes).ok();
        }
    }
    None
}

/// The double `0.digits` times 10^(exponent + 1) reads as.
fn reads_back(digits: &str, exponent: i32) -> Option<f64> {
    let (first, rest) = digits.split_at(1);
    format!("{first}.{rest}e{exponent}").parse().ok()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn double(bits: u64) -> String {
        canonical(&Value::Number(
            Number::from_f64(f64::from_bits(bits)).expect("a finite double"),
        ))
    }

    /// RFC 8785, appendix B: the IEEE 754 doubles and how ECMAScript writes each.
    #[test]
    fn doubles_are_written_as_ecmascript_writes_them() {
        for (bits, written) in [
            (0x0000_0000_0000_0000, "0"),
            (0x8000_0000_0000_0000, "0"),
            (0x0000_0000_0000_0001, "5e-324"),
            (0x8000_0000_0000_0001, "-5e-324"),
            (0x7fef_ffff_ffff_ffff, "1.7976931348623157e+308"),
            (0xffef_ffff_ffff_ffff, "-1.7976931348623157e+308"),
            (0x4340_0000_0000_0000, "9007199254740992"),
            (0xc340_0000_0000_0000, "-9007199254740992"),
            (0x4430_0000_0000_0000, "295147905179352830000"),
            (0x44b5_2d02_c7e1_4af5, "9.999999999999997e+22"),
            (0x44b5_2d02_c7e1_4af6, "1e+23"),
            (0x44b5_2d02_c7e1_4af7, "1.0000000000000001e+23"),
            (0x444b_1ae4_d6e2_ef4e, "999999999999999700000"),
            (0x444b_1ae4_d6e2_ef4f, "999999999999999900000"),
            (0x444b_1ae4_d6e2_ef50, "1e+21"),
            (0x3eb0_c6f7_a0b5_ed8c, "9.999999999999997e-7"),
            (0x3eb0_c6f7_a0b5_ed8d, "0.000001"),
            (0x41b3_de43_5555_5553, "333333333.3333332"),
            (0x41b3_de43_5555_5554, "333333333.33333325"),
            (0x41b3_de43_5555_5555, "333333333.3333333"),
            (0x41b3_de43_5555_5556, "333333333.3333334"),
            (0x41b3_de43_5555_5557, "333333333.33333343"),
            (0xbecb_f647_612f_3696, "-0.0000033333333333333333"),
            (0x4314_3ff3_c1cb_0959, "1424953923781206.2"),
        ] {
            assert_eq!(double(bits), written, "{bits:#018x}");
        }
    }

    #[test]
    fn integers_are_written_exactly() {
        let beyond = 9_007_199_254_740_993_u64;
        assert_eq!(canonical(&json!(beyond)), "9007199254740993");
        assert_eq!(canonical(&json!(u64::MAX)), "18446744073709551615");
        assert_eq!(canonical(&json!(i64::MIN)), "-9223372036854775808");
        assert_eq!(canonical(&json!(-1)), "-1");
        // A double with a whole value is written as ECMAScript writes it.
        assert_eq!(canonical(&json!(2.0)), "2");
    }

    /// RFC 8785, section 3.2.3: names sorted by UTF-16 code units. The emoji sorts before
    /// U+FB33 in UTF-16 and after it in UTF-8.
    #[test]
    fn members_are_sorted_by_utf16_code_units() {
        let value: Value = serde_json::from_str(
            r#"{"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", "\ud83d\ude00": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis"}"#,
        )
        .expect("the example parses");
        assert_eq!(
            canonical(&value),
            "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
             \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
             \"\u{1f600}\":\"Emoji: Grinning Face\",\
             \"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}"
        );
    }

    /// RFC 8785, section 3.2.4's example, apart from its numbers, which it writes as doubles.
    #[test]
    fn strings_and_literals_are_written_canonically() {
        let value: Value = serde_json::from_str(
            r#"{"string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/", "literals": [null, true, false]}"#,
        )
        .expect("the example parses");
        assert_eq!(
            canonical(&value),
            "{\"literals\":[null,true,false],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
        assert_eq!(
            canonical(&json!("\u{8}\t\n\u{c}\r\u{0}\u{1f}\u{7f}\u{2028}")),
            "\"\\b\\t\\n\\f\\r\\u0000\\u001f\u{7f}\u{2028}\""
        );
    }

    #[test]
    fn whitespace_and_order_do_not_matter() {
        let one: Value =
            serde_json::from_str("{ \"b\" : [1, 2.5, {\"y\": null, \"x\": true}], \"a\": \"t\" }")
                .expect("parses");
        let other: Value =
            serde_json::from_str("{\"a\":\"t\",\"b\":[1,2.5,{\"x\":true,\"y\":null}]}")
                .expect("parses");
        assert_eq!(canonical(&one), canonical(&other));
        assert_eq!(
            canonical(&one),
            "{\"a\":\"t\",\"b\":[1,2.5,{\"x\":true,\"y\":null}]}"
        );
    }
}
