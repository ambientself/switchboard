// A refusal's sentence cannot be replaced after its row is written.

use gateway_core::audit::Refusal;

fn rewrite(refusal: &mut Refusal) {
    refusal.sentence = String::new();
}

fn main() {}
