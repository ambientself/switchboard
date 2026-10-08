//! An audit store that prints each row as it is written.

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use gateway_core::audit::{AuditRowId, RowCompletion, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};
use gateway_testkit::InMemoryAuditStore;
use serde_json::{Value, json};

/// An [`AuditStore`] over an [`InMemoryAuditStore`] that writes one JSON line for each thing the
/// store does, once it has done it:
///
/// - `{"audit": "begun", "row": ..., "record": {...}}` when a row is written;
/// - `{"audit": "finished", "row": ..., "completion": {...}}` when it is completed;
/// - `{"audit": "begin_failed", "error": ...}` and `{"audit": "finish_failed", "row": ...,
///   "error": ...}` when the store fails.
///
/// The store's result is passed on unchanged. A failed begin stays a failure, so the call is
/// refused as it would be without the printer. A line that cannot be written is dropped:
/// printing never changes what the store did.
pub struct AuditPrinter {
    store: Arc<InMemoryAuditStore>,
    out: Mutex<Box<dyn Write + Send>>,
}

impl AuditPrinter {
    /// Prints what `store` does to `out`.
    pub fn new(store: Arc<InMemoryAuditStore>, out: Box<dyn Write + Send>) -> Self {
        Self {
            store,
            out: Mutex::new(out),
        }
    }

    fn print(&self, line: &Value) {
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

impl std::fmt::Debug for AuditPrinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditPrinter").finish_non_exhaustive()
    }
}

impl AuditStore for AuditPrinter {
    fn begin<'a>(
        &'a self,
        record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<AuditRowId, StoreError>> {
        Box::pin(async move {
            let begun = self.store.begin(record).await;
            match &begun {
                Ok(row) => self.print(&json!({"audit": "begun", "row": row, "record": record})),
                Err(error) => {
                    self.print(&json!({"audit": "begin_failed", "error": error.to_string()}));
                }
            }
            begun
        })
    }

    fn finish<'a>(
        &'a self,
        completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let finished = self.store.finish(completion).await;
            let row = completion.row();
            match &finished {
                Ok(()) => self.print(&json!({
                    "audit": "finished",
                    "row": row,
                    "completion": completion.completion(),
                })),
                Err(error) => self.print(&json!({
                    "audit": "finish_failed",
                    "row": row,
                    "error": error.to_string(),
                })),
            }
            finished
        })
    }
}
