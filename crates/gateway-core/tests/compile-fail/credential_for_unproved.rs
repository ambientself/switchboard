// A credential is asked for on behalf of a proved principal. A plain principal, such as one
// built from a deserialized row or by hand, cannot stand in.

use gateway_core::{BoxFuture, ConnectorName, CredentialError, CredentialHandle};
use gateway_core::{CredentialSource, Principal};

fn ask(
    source: &dyn CredentialSource,
    connector: &ConnectorName,
    caller: &Principal,
) -> BoxFuture<'static, Result<CredentialHandle, CredentialError>> {
    let _ = source.credential_for(connector, caller);
    unimplemented!()
}

fn main() {}
