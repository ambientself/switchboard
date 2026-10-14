//! The audit store used when configuration explicitly turns audit off.

use gateway_core::audit::{AuditRowId, ListRecord, RowCompletion, StoreError};
use gateway_core::receipt::{ReceiptRequest, Reservation};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};

/// An [`AuditStore`] that writes nothing, for a deployment whose configuration says
/// `"audit": {"disabled": true}`.
///
/// It breaks the store's contract on purpose: `begin` and `list` return `Ok` and no row
/// exists. That is what the opt-out means, and only a test-support build accepts it, with a
/// loud warning (design section 12, decision 0014); the release build refuses to start with
/// audit disabled, and CI checks that refusal. So the type has no public constructor. The boot
/// gates make one when, and only when, a test-support build's configuration opts out, and no
/// other code path can put it where a real store belongs. The identifier the gateway made for
/// a row is carried through the call as usual and stored nowhere.
#[derive(Debug)]
pub struct DisabledAuditStore {
    _opted_out: (),
}

impl DisabledAuditStore {
    pub(crate) fn new() -> Self {
        Self { _opted_out: () }
    }
}

impl AuditStore for DisabledAuditStore {
    fn begin<'a>(
        &'a self,
        _row: &'a AuditRowId,
        _record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }

    /// Refused: a receipt is what stops a side effect running twice, and a store that writes
    /// nothing keeps none, so no call of a tool not classified `read` runs with audit disabled
    /// (decision 0009, "Until receipts exist").
    fn begin_with_receipt<'a>(
        &'a self,
        _row: &'a AuditRowId,
        _record: &'a AuditRecord,
        _receipt: &'a ReceiptRequest,
    ) -> BoxFuture<'a, Result<Reservation, StoreError>> {
        Box::pin(async {
            Err("audit is disabled, so no receipt can be kept and no side effect runs".into())
        })
    }

    fn finish<'a>(
        &'a self,
        _completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn list<'a>(
        &'a self,
        _row: &'a AuditRowId,
        _record: &'a ListRecord,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
}
