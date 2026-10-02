// A claimed principal or delegation cannot stand where policy requires a proved one.

use gateway_core::{CallerContext, Claimed, Delegation, Principal};

fn context(principal: Claimed<Principal>, delegation: Claimed<Delegation>) -> CallerContext {
    CallerContext {
        principal,
        delegation: Some(delegation),
        profile: "otto".into(),
        surface: "otto-sandbox".into(),
        deployment: "test".into(),
    }
}

fn main() {}
