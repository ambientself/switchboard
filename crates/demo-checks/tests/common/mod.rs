//! Paths and scratch space shared by the tests.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A file in the repository, read as text.
pub fn read(relative: &str) -> String {
    let path = repo().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// A new, empty directory for one test.
pub fn scratch(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("demo-checks-{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|error| panic!("create {}: {error}", dir.display()));
    dir
}

/// Writes `contents` to `dir/name` and returns the path.
pub fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents)
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    path
}

/// Fails the test, naming the tool, when a tool the scripts need is missing.
pub fn require(tools: &[&str]) {
    for tool in tools {
        let found = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {tool}"))
            .output()
            .is_ok_and(|output| output.status.success());
        assert!(
            found,
            "these tests run the demo scripts, which need `{tool}` on PATH"
        );
    }
}

/// A port that accepts connections and never answers: what a dropped route looks like to curl,
/// which then times out (exit 28).
pub fn black_hole() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    format!("http://127.0.0.1:{port}/mcp")
}

/// A server on a free loopback port that answers every request with an HTTP status and no
/// body, and keeps the head of each request it was sent.
pub struct Recorder {
    pub url: String,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    pub fn start(status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&heads);
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let kept = Arc::clone(&kept);
                thread::spawn(move || {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let end = loop {
                        let n = match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buffer.extend_from_slice(&chunk[..n]);
                        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                            break at + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
                    let length: usize = head
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().ok())?
                        })
                        .unwrap_or(0);
                    while buffer.len() < end + length {
                        match stream.read(&mut chunk) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                        }
                    }
                    kept.lock().unwrap().push(head);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                });
            }
        });
        Recorder {
            url: format!("http://127.0.0.1:{port}/mcp"),
            heads,
        }
    }

    /// The head of each request so far.
    pub fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

/// A fake `getent` for the route probe: `getent ahosts NAME` answers from the file
/// `$FAKE_HOSTS`, one `NAME ADDRESS` per line, as glibc prints it. The address `slow` is a lookup
/// that times out: it waits, then finds nothing. Any other name does not resolve.
pub const FAKE_GETENT: &str = r#"#!/bin/sh
[ "$1" = ahosts ] || exit 1
status=2
while read -r name address; do
  [ "$name" = "$2" ] || continue
  if [ "$address" = slow ]; then sleep 2; exit 2; fi
  printf '%s       STREAM %s\n%s       DGRAM\n%s       RAW\n' "$address" "$2" "$address" "$address"
  status=0
done <"${FAKE_HOSTS:-/dev/null}"
exit $status
"#;

/// Writes the fake `getent` into `bin`.
pub fn fake_getent(bin: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let path = write(bin, "getent", FAKE_GETENT);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A port nothing listens on: curl's connection is refused (exit 7).
pub fn closed_port() -> String {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("http://127.0.0.1:{port}/mcp")
}

/// What a script printed and how it ended.
pub struct Run {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    pub fn from(output: std::process::Output) -> Self {
        Run {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// The lines that start with `prefix`.
    pub fn lines(&self, prefix: &str) -> Vec<&str> {
        self.stdout
            .lines()
            .filter(|line| line.starts_with(prefix))
            .collect()
    }

    /// Whether a FAIL line contains `text`.
    pub fn failed(&self, text: &str) -> bool {
        self.lines("FAIL ").iter().any(|line| line.contains(text))
    }

    /// Everything printed, for assertion messages.
    pub fn transcript(&self) -> String {
        format!(
            "exit {:?}\n--- stdout\n{}--- stderr\n{}",
            self.status, self.stdout, self.stderr
        )
    }
}
