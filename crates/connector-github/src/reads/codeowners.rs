//! Who CODEOWNERS says owns a path, read as GitHub reads the file.
//!
//! Each line is a pattern and its owners; `#` starts a comment, at the start of a line or after
//! whitespace, and `\#` starts a pattern that begins with `#`. The last line whose pattern
//! matches the path decides, and a line with a pattern and no owner leaves the path unowned. An
//! owner is a word with an `@` in it: `@user`, `@org/team` or an email address.
//!
//! Patterns follow the gitignore rules GitHub applies: `*` matches within a path segment, `?`
//! one character of one, and `**` any number of segments; a leading `/`, or a `/` before the
//! end, anchors a pattern at the root, and one with no `/` matches at any depth; a trailing `/`
//! matches only a directory's contents; a pattern that matches a directory matches everything
//! in it. Matching is case-sensitive. GitHub does not support `!` and `[...]` in CODEOWNERS, so a
//! line starting with `!` is skipped and `[` is an ordinary character.

/// The owners the last line of `text` whose pattern matches `path` names; empty when none
/// matches, or the last that matches names no owner.
pub(crate) fn owners(text: &str, path: &str) -> Vec<String> {
    let path: Vec<&str> = path.split('/').collect();
    let mut found = Vec::new();
    for line in text.lines() {
        let mut words = uncommented(line).split_whitespace();
        let Some(pattern) = words.next() else {
            continue;
        };
        if pattern.starts_with('!') {
            continue;
        }
        let pattern = pattern.strip_prefix('\\').unwrap_or(pattern);
        if matches(pattern, &path) {
            found = words
                .filter(|word| word.len() > 1 && word.contains('@'))
                .map(str::to_owned)
                .collect();
        }
    }
    found
}

/// `line` up to its comment.
fn uncommented(line: &str) -> &str {
    let line = line.trim_start();
    if line.starts_with('#') {
        return "";
    }
    let bytes = line.as_bytes();
    for index in 1..bytes.len() {
        if bytes[index] == b'#' && bytes[index - 1].is_ascii_whitespace() {
            return &line[..index];
        }
    }
    line
}

/// Whether `pattern` matches `path`, its segments.
fn matches(pattern: &str, path: &[&str]) -> bool {
    let directory_only = pattern.ends_with('/');
    let trimmed = pattern.trim_end_matches('/');
    let anchored = trimmed.contains('/');
    let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return false;
    }
    let segments: Vec<&str> = trimmed.split('/').collect();
    if anchored {
        prefix(&segments, path, directory_only)
    } else {
        (0..path.len()).any(|start| prefix(&segments, &path[start..], directory_only))
    }
}

/// Whether `pattern` matches the whole of `path`, or a directory `path` is inside.
fn prefix(pattern: &[&str], path: &[&str], directory_only: bool) -> bool {
    match pattern.split_first() {
        None => !path.is_empty() || !directory_only,
        Some((&"**", rest)) => {
            (0..=path.len()).any(|skip| prefix(rest, &path[skip..], directory_only))
        }
        Some((first, rest)) => path.split_first().is_some_and(|(segment, path)| {
            glob(first.as_bytes(), segment.as_bytes()) && prefix(rest, path, directory_only)
        }),
    }
}

/// Whether `pattern`, with `*` and `?`, matches all of `text`, one segment.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|skip| glob(rest, &text[skip..])),
        Some((b'?', rest)) => !text.is_empty() && glob(rest, &text[1..]),
        Some((byte, rest)) => text.first() == Some(byte) && glob(rest, &text[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(text: &str) -> bool {
        !owners(text, "AGENTS.md").is_empty()
    }

    #[test]
    fn a_root_file_is_owned_by_the_lines_that_match_it() {
        for text in [
            "AGENTS.md @org/owners",
            "/AGENTS.md @org/owners",
            "* @org/owners",
            "/* @org/owners",
            "*.md @someone",
            "** owner@example.test",
            "**/AGENTS.md @org/owners",
            "AGENTS.?? @org/owners",
            "\n# a comment\n\nAGENTS.md @org/owners # and one here\n",
        ] {
            assert!(owned(text), "{text:?}");
        }
    }

    #[test]
    fn a_root_file_is_not_owned_by_lines_that_do_not_match_it() {
        for text in [
            "",
            "# AGENTS.md @org/owners",
            "/docs/ @org/docs",
            "AGENTS.md/ @org/owners",
            "/agents.md @org/owners",
            "docs/AGENTS.md @org/owners",
            "*.txt @org/owners",
            "!AGENTS.md @org/owners",
            // The last matching line decides, and it names no owner.
            "* @org/owners\nAGENTS.md",
            // A word with no @ is not an owner.
            "AGENTS.md owners",
        ] {
            assert!(!owned(text), "{text:?}");
        }
    }

    #[test]
    fn the_last_matching_line_decides() {
        assert_eq!(
            owners("* @a\n*.md @b @c\n/docs/ @d", "AGENTS.md"),
            ["@b", "@c"]
        );
        assert_eq!(owners("* @a\n/docs/ @d", "docs/x/AGENTS.md"), ["@d"]);
        assert_eq!(owners("docs @d", "docs/AGENTS.md"), ["@d"]);
        assert_eq!(owners("docs/** @d", "docs/a/b"), ["@d"]);
        assert!(owners("/docs/ @d", "docs").is_empty());
    }
}
