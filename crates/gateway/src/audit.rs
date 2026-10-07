//! The audit store used when configuration explicitly turns audit off.

use gateway_core::audit::{AuditRowId, RowCompletion, StoreError};
use gateway_core::{AuditRecord, AuditStore, BoxFuture};

/// The row identifier [`DisabledAuditStore`] hands out for every row.
pub const DISABLED_ROW: &str = "audit-disabled";

/// An [`AuditStore`] that writes nothing, for a deployment whose configuration says
/// `"audit": {"disabled": true}`.
///
/// It breaks the store's contract on purpose: `begin` returns `Ok` and no row exists. That is
/// what the opt-out means, and design section 12 lets a gateway start that way only with a loud
/// warning. So the type has no public constructor. [`boot::check`](crate::boot::check) makes
/// one when, and only when, configuration opts out, and no other code path can put it where a
/// real store belongs. Every row it is given gets the identifier [`DISABLED_ROW`].
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
        _record: &'a AuditRecord,
    ) -> BoxFuture<'a, Result<AuditRowId, StoreError>> {
        Box::pin(async { Ok(AuditRowId::new(DISABLED_ROW)) })
    }

    fn finish<'a>(
        &'a self,
        _completion: &'a RowCompletion,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(async { Ok(()) })
    }
}
