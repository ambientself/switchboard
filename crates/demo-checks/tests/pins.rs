//! Every Postgres image the repository names is the same Postgres. demo.sh's `POSTGRES_IMAGE` is
//! the reference. Every image names its release, and any that names its tag with a digest names
//! its digest too. Compose and the commands in CONTRIBUTING.md and the audit store's crate
//! documentation name it exactly, the kind manifest names its tag alone, and CI's service
//! container, another variant of the same release, is pinned by a digest of its own. A bump that
//! misses one of them fails here. The kind manifest's pod template carries the digest as an
//! annotation that demo.sh fills in, so a new digest under the same tag rolls the pod.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::read;

/// Where the repository names a Postgres image, and how each place must name it.
const PLACES: [(&str, Pin); 6] = [
    ("deploy/demo/demo.sh", Pin::Exact),
    ("deploy/compose/compose.yaml", Pin::Exact),
    ("CONTRIBUTING.md", Pin::Exact),
    ("crates/audit-postgres/src/lib.rs", Pin::Exact),
    ("deploy/kind/base/postgres.yaml", Pin::Tag),
    (".github/workflows/ci.yml", Pin::Version),
];

#[derive(Clone, Copy, Debug, PartialEq)]
enum Pin {
    /// demo.sh's reference, tag and digest, at least once.
    Exact,
    /// demo.sh's tag, with no digest, every time: kind's image load does not keep the index
    /// digest.
    Tag,
    /// demo.sh's release, pinned by a digest of its own every time.
    Version,
}

/// Every `postgres:<version>...` image reference in `text`, up to the next space, quote, backtick
/// or bracket. A connection URL's `postgres:<password>@` is not one, because a version starts
/// with a digit, and nor is its `@postgres:<port>`, a host named postgres.
fn references(text: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("postgres:") {
        let host = rest[..at].ends_with('@');
        let from = &rest[at..];
        rest = &from["postgres:".len()..];
        if host || !rest.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let end = from
            .find(|c: char| c.is_whitespace() || "`\"'()[]{},".contains(c))
            .unwrap_or(from.len());
        found.push(&from[..end]);
    }
    found
}

/// The release a reference names: its tag up to the variant, `17.11` for `postgres:17.11-alpine`.
fn version(reference: &str) -> &str {
    let tag = reference.split('@').next().unwrap_or_default();
    let tag = tag.strip_prefix("postgres:").unwrap_or(tag);
    tag.split('-').next().unwrap_or_default()
}

/// The digest of `name:tag@sha256:<digest>`, failing unless it is 64 hex digits.
fn digest<'a>(reference: &'a str, place: &str) -> &'a str {
    let (_, digest) = reference
        .split_once("@sha256:")
        .unwrap_or_else(|| panic!("{place}: {reference} is not pinned by digest"));
    assert!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "{place}: {reference} has no sha256 digest"
    );
    digest
}

/// demo.sh's `POSTGRES_IMAGE`, the reference every other place is held to.
fn pinned() -> String {
    let driver = read("deploy/demo/demo.sh");
    let lines: Vec<&str> = driver
        .lines()
        .filter_map(|line| line.strip_prefix("POSTGRES_IMAGE="))
        .collect();
    assert_eq!(lines.len(), 1, "demo.sh's POSTGRES_IMAGE lines: {lines:?}");
    let reference = lines[0].trim_end().to_owned();
    digest(&reference, "demo.sh's POSTGRES_IMAGE");
    assert!(
        reference.starts_with("postgres:") && reference.contains('-'),
        "demo.sh's POSTGRES_IMAGE is not a postgres tag with a variant: {reference}"
    );
    reference
}

#[test]
fn every_postgres_pin_names_the_same_version_and_digest() {
    let reference = pinned();
    let tag = reference.split('@').next().unwrap();
    let release = version(&reference);
    assert!(
        release.contains('.') && release.split('.').all(|part| part.parse::<u32>().is_ok()),
        "demo.sh's POSTGRES_IMAGE names no exact release: {reference}"
    );
    for (place, pin) in PLACES {
        let text = read(place);
        let found = references(&text);
        assert!(!found.is_empty(), "{place} names no Postgres image");
        for image in &found {
            assert_eq!(
                version(image),
                release,
                "{place} names Postgres {image}, not demo.sh's release {release}"
            );
            if image.split('@').next() == Some(tag) && image.contains('@') {
                assert_eq!(
                    *image, reference,
                    "{place} names {image}, not demo.sh's digest for {tag}"
                );
            }
            match pin {
                Pin::Exact => {}
                Pin::Tag => assert_eq!(
                    *image, tag,
                    "{place} names {image}, not demo.sh's tag {tag} alone"
                ),
                Pin::Version => {
                    digest(image, place);
                }
            }
        }
        if pin == Pin::Exact {
            assert!(
                found.contains(&reference.as_str()),
                "{place} does not name demo.sh's {reference}: {found:?}"
            );
        }
    }
}

#[test]
fn the_reference_scan_finds_images_and_skips_connection_urls() {
    let text = "docker run postgres:17.11-alpine@sha256:ab \\\n\
                URL=postgres://postgres:dev@127.0.0.1:25432/postgres\n\
                URL=postgres://gateway:dummy@postgres:5432/switchboard\n\
                a `postgres:17.11` service, image: \"postgres:16\"\n";
    assert_eq!(
        references(text),
        [
            "postgres:17.11-alpine@sha256:ab",
            "postgres:17.11",
            "postgres:16"
        ]
    );
    assert_eq!(version("postgres:17.11-alpine@sha256:ab"), "17.11");
    assert_eq!(version("postgres:17-alpine"), "17");
}

#[test]
fn the_kind_postgres_pod_carries_the_digest_and_never_pulls() {
    let manifest = read("deploy/kind/base/postgres.yaml");
    // The annotation sits in the pod template, where a change rolls the pod; demo.sh's
    // apply_base replaces its value with POSTGRES_IMAGE's digest (driver.rs runs that).
    let annotations: Vec<&str> = manifest
        .lines()
        .filter(|line| {
            line.trim_start()
                .starts_with("switchboard.io/image-digest:")
        })
        .collect();
    assert_eq!(annotations.len(), 1, "{manifest}");
    let metadata = manifest
        .split_once("  template:\n")
        .and_then(|(_, template)| template.split_once("    spec:\n"))
        .expect("the Postgres Deployment has a pod template with a spec")
        .0;
    assert!(
        metadata.contains(&format!("      annotations:\n{}\n", annotations[0])),
        "the digest annotation is not in the pod template's metadata: {metadata}"
    );
    // demo.sh loads the image before it applies the manifest. A pod that cannot find it must
    // stop, not pull whatever the tag names on Docker Hub today.
    let policies: Vec<&str> = manifest
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("imagePullPolicy: "))
        .collect();
    assert_eq!(policies, ["Never"], "{manifest}");
}
