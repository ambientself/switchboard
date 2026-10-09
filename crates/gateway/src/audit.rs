//! The audit store used when configuration explicitly turns audit off.

use gateway_core::audit::{AuditRowId, ListRecord, RowCompletion, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};

/// An [`AuditStore`] that writes nothing, for a deployment whose configuration says
/// `"audit": {"disabled": true}`.
///
/// It breaks the store's contract on purpose: `begin` and `list` return `Ok` and no row
/// exists. That is what the opt-out means, and design section 12 lets a gateway start that way
/// only with a loud warning. So the type has no public constructor. [`boot::check`](crate::boot::check) makes
/// one when, and only when, configuration opts out, and no other code path can put it where a
/// real store belongs. The identifier the gateway made for a row is carried through the call
/// as usual and stored nowhere.
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
