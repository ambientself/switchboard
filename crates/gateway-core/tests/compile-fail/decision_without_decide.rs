// An allowed decision cannot be built by hand, so the checks cannot be skipped on the way to
// the audit begin step.

use gateway_core::{ApprovedTool, CallContext, Decision, PolicyRevision, Verdict};

fn skip_checks(call: CallContext, tool: ApprovedTool) -> Decision {
    Decision {
        call,
        verdict: Verdict::Allow(tool),
        policy_revision: PolicyRevision::new("r1"),
    }
}

fn main() {}
