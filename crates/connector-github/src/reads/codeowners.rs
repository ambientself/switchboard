//! Who CODEOWNERS says owns a path, read as GitHub reads the file.
//!
//! Each line is a pattern and its owners; `#` starts a comment, at the start of a line or after
//! whitespace, and `\#` starts a pattern that begins with `#`. The last line whose pattern
//! matches the path decides, and a line with a pattern and no owner leaves the path unowned. An
//! owner is a word with an `@` in it: `@user`, `@org/team` or an email address.
//!
//! Patterns follow the gitignore rules GitHub applies: `*` matches within a path segment, `?`
//! one character of one, and `**` any number of segments; a leading `/`, or a `/` before the
//! end, anchors a pattern at the root, and one with no `/` matches at any depth; a trailing `/`,
//! or `/**`, matches only a directory's contents, not a file of that name; a pattern that
//! matches a directory matches everything in it. Matching is case-sensitive. GitHub does not
//! support `!` and `[...]` in CODEOWNERS, so a line starting with `!` is skipped and `[` is an
//! ordinary character.

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
///
/// Neither this nor [`glob`] recurses. This does not backtrack, and [`glob`] backs up only to
/// just after the last `*` in a segment, so the work is at most the pattern's length times the
/// path's, and the stack does not grow with either: a hostile CODEOWNERS file cannot hold a
/// worker or overflow its stack.
fn matches(pattern: &str, path: &[&str]) -> bool {
    let mut directory_only = pattern.ends_with('/');
    let trimmed = pattern.trim_end_matches('/');
    let anchored = trimmed.contains('/');
    let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
    if trimmed.is_empty() {
        return false;
    }
    let mut segments: Vec<&str> = trimmed.split('/').collect();
    // `**/**` is `**`.
    segments.dedup_by(|next, previous| *next == "**" && *previous == "**");
    // A trailing `/**` matches everything inside, and not the directory or file itself.
    if segments.len() > 1 && segments.last() == Some(&"**") {
        segments.pop();
        directory_only = true;
    }
    // `reached[at]`: the segments so far match `path[start..at]` for some start the pattern may
    // begin at, the root's when anchored and any segment's when not.
    let mut reached: Vec<bool> = (0..=path.len())
        .map(|at| at == 0 || (!anchored && at < path.len()))
        .collect();
    for segment in segments {
        if segment == "**" {
            let mut any = false;
            for at in &mut reached {
                any |= *at;
                *at = any;
            }
        } else {
            for at in (1..=path.len()).rev() {
                reached[at] = reached[at - 1] && glob(segment.as_bytes(), path[at - 1].as_bytes());
            }
            reached[0] = false;
        }
    }
    // The pattern matches the whole path, or a directory the path is inside.
    (1..=path.len()).any(|at| reached[at] && (at < path.len() || !directory_only))
}

/// Whether `pattern`, with `*` and `?`, matches all of `text`, one segment: the usual
/// two-pointer match, which goes back only to just after the last `*`.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    // The last `*` seen, and where in `text` what it matches would end.
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&byte) if byte == b'?' || byte == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((at, end)) => {
                    star = Some((at, end + 1));
                    p = at + 1;
                    t = end + 1;
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
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
            "**/** @org/owners",
            "*A*G*E*N*T*S*.*m*d* @org/owners",
            "/**/AGENTS.md @org/owners",
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
            // A trailing `/**` matches what is inside, not the file itself.
            "AGENTS.md/** @org/owners",
            "/AGENTS.md/** @org/owners",
            "*/** @org/owners",
            "*.md/** @org/owners",
            "AGENTS.md/**/** @org/owners",
            "AGENTS.md\n*/** @org/owners",
            "AGENTS.mdx @org/owners",
            "?AGENTS.md @org/owners",
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
        assert_eq!(owners("docs/**/x @d", "docs/x"), ["@d"]);
        assert_eq!(owners("docs/**/x @d", "docs/a/b/x"), ["@d"]);
        assert_eq!(owners("**/x/** @d", "a/x/b"), ["@d"]);
        assert!(owners("**/x/** @d", "a/x").is_empty());
        assert!(owners("docs/** @d", "docs").is_empty());
        assert_eq!(owners("a*b*c @d", "a-b-b-c"), ["@d"]);
        assert!(owners("a*b*c @d", "a-b-b-cx").is_empty());
    }

    /// A pattern that would take a backtracking matcher billions of steps, or a recursive one
    /// more stack than a worker has, is matched at once: these run on the test's own thread.
    #[test]
    fn hostile_patterns_are_matched_in_bounded_work() {
        let stars = format!("{}X @org/owners", "*".repeat(50));
        assert!(!owned(&stars));
        let many_stars = format!("{}X @org/owners", "*".repeat(100_000));
        assert!(!owned(&many_stars));
        let many_globstars = format!("{}X @org/owners", "**/".repeat(200_000));
        assert!(!owned(&many_globstars));
        let lines = format!("{}X @org/owners\n", "*?".repeat(25)).repeat(1_000);
        assert!(!owned(&lines));
        let segments = format!("{}AGENTS.md @org/owners", "*/".repeat(100_000));
        assert!(!owned(&segments));
        // They still match what they should.
        assert!(owned(&format!(
            "{}AGENTS.md @org/owners",
            "**/".repeat(200_000)
        )));
        assert!(owned(&format!(
            "{}AGENTS.md @org/owners",
            "*".repeat(100_000)
        )));
    }
}
