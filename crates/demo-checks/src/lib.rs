//! Tests for the demo's deployment in `deploy/`. The crate has no code of its own; its tests
//! run the shell scripts and read the manifests:
//!
//! - `tests/workload.rs` runs `deploy/demo/workload.sh` against a fake gateway that can
//!   misbehave in one way at a time, and requires every misbehaviour to end in a FAIL line and a
//!   non-zero exit.
//! - `tests/driver.rs` runs `deploy/demo/demo.sh` with fake `docker`, `kind` and `kubectl`, and
//!   requires it to refuse the cluster `otto-dev`, to name its own kubeconfig in every call, and
//!   to count every failure.
//! - `tests/manifests.rs` holds the Compose file and the kind manifests to what the demo claims:
//!   only the gateway is published, and only on loopback; the network policy admits only the
//!   gateway; in kind the gateway presents its own projected token and mock-docs accepts only
//!   that identity; Compose's dummy credential's hash matches it.
//!
//! The scripts need `sh`, `bash`, `curl`, `jq` and `awk`, which CI's runners have.
