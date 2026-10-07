// A credential is asked for on behalf of a proved principal. A claimed one, such as a team
// read from a header, cannot stand in.

use gateway_core::{BoxFuture, Claimed, ConnectorName, CredentialError, CredentialHandle};
use gateway_core::{CredentialSource, Principal};

fn ask(
    source: &dyn CredentialSource,
    connector: &ConnectorName,
    caller: &Claimed<Principal>,
) -> BoxFuture<'static, Result<CredentialHandle, CredentialError>> {
    let _ = source.credential_for(connector, caller);
    unimplemented!()
}

fn main() {}
