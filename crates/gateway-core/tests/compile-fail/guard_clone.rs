// A guard cannot be copied to run its call twice.

use gateway_core::AuditGuard;

fn copy(guard: &AuditGuard) -> AuditGuard {
    guard.clone()
}

fn main() {}
