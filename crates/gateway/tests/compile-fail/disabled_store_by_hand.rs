// The no-op audit store cannot be made by hand. Only the boot gates make one, and only when
// configuration opts out of audit, so it cannot stand in for a store that was configured.

use gateway::DisabledAuditStore;

fn main() {
    let _store = DisabledAuditStore::new();
}
