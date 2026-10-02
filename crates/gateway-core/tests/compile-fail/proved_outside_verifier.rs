// Outside a verifier, there is no way to make a proved value: not by its constructor, not by
// a `new`, not by conversion and not by default.

use gateway_core::{Principal, Proved};

fn fabricate(principal: Principal) {
    let _ = Proved(principal.clone());
    let _ = Proved::new(principal.clone());
    let _: Proved<Principal> = Proved::from(principal);
    let _: Proved<Principal> = Default::default();
}

fn main() {}
