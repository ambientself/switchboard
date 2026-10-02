// A claimed principal or delegation cannot stand where policy requires a proved one.

use gateway_core::{CallerContext, Claimed, Delegation, Principal, Profile};

fn context(principal: Claimed<Principal>, delegation: Claimed<Delegation>, profile: Profile) -> CallerContext {
    CallerContext {
        principal,
        delegation: Some(delegation),
        profile,
        surface: "otto-sandbox".into(),
        deployment: "test".into(),
    }
}

fn main() {}
