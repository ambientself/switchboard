// Gates cannot be built by hand: the only way to hold one is to have passed `boot::check`, so
// nothing that takes `Gates` can serve a configuration the boot gates refused.

use gateway::Gates;

fn main() {
    let _gates = Gates {};
}
