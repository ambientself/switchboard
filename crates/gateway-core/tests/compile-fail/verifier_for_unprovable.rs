// A verifier may prove a principal or a delegation, and nothing else. A proved team exists
// only as part of one of those.

use std::convert::Infallible;

use gateway_core::{TeamId, Verifier};

struct TeamFromHeader;

impl Verifier for TeamFromHeader {
    type Evidence = str;
    type Fact = TeamId;
    type Error = Infallible;

    fn verify(&self, evidence: &str) -> Result<TeamId, Infallible> {
        Ok(TeamId::new(evidence))
    }
}

fn main() {}
