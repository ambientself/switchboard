//! Identity from files (issue #9, steps 9b and 9c): a token shaped like a projected Kubernetes
//! ServiceAccount token, verified against keys and a team manifest read from files, and a key
//! rotation done by rewriting the keys file and restarting.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod files;

use std::sync::{Arc, OnceLock};

use files::{
    AUDIENCE, CLUSTER_ISSUER, Files, STRANGER_SA, TEAM_A_SA, TEAM_B_SA, cluster_issuer, key_set,
    kubernetes_token,
};
use gateway::Gates;
use gateway_core::PrincipalKind;
use gateway_identity::{SystemClock, Verification, VerifyError};
use gateway_testkit::LocalIssuer;

fn issuer() -> &'static LocalIssuer {
    static ISSUER: OnceLock<LocalIssuer> = OnceLock::new();
    ISSUER.get_or_init(cluster_issuer)
}

/// The gates for the deployment in `files`, as the binary would build them.
async fn gates(files: &Files) -> Gates {
    gateway::start::prepare(files.load(), Arc::new(SystemClock))
        .await
        .unwrap()
        .gates
}

/// The team a token proves, or the check that refused it.
fn team_of(gates: &Gates, token: &str) -> Result<String, VerifyError> {
    match gates.identity().check(Some(token)) {
        Verification::Proved(principal) => {
            let principal = principal.get();
            assert_eq!(principal.id.issuer.as_str(), CLUSTER_ISSUER);
            match &principal.kind {
                PrincipalKind::Workload { team } => Ok(team.as_str().to_owned()),
                other => panic!("a workload issuer proved {other:?}"),
            }
        }
        Verification::Failed(failure) => Err(failure.detail().clone()),
        Verification::Disabled => panic!("identity is enforced"),
    }
}

#[tokio::test]
async fn a_projected_service_account_token_proves_its_team() {
    let files = Files::new(
        "kubernetes",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let gates = gates(&files).await;
    // A projected token: `aud` an array, `jti`, `nbf`, and the `kubernetes.io` claim.
    for (subject, team) in [(TEAM_A_SA, "team-a"), (TEAM_B_SA, "team-b")] {
        let token = kubernetes_token(issuer(), subject, &[AUDIENCE]);
        assert_eq!(team_of(&gates, &token), Ok(team.to_owned()), "{subject}");
    }
    // Several audiences, one of them ours.
    let token = kubernetes_token(issuer(), TEAM_A_SA, &[CLUSTER_ISSUER, AUDIENCE]);
    assert_eq!(team_of(&gates, &token), Ok("team-a".to_owned()));
}

#[tokio::test]
async fn a_real_token_outside_the_manifest_or_for_another_audience_is_refused() {
    let files = Files::new(
        "kubernetes-refused",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let gates = gates(&files).await;
    // A ServiceAccount in the right namespace that the team manifest does not list.
    let stranger = kubernetes_token(issuer(), STRANGER_SA, &[AUDIENCE]);
    assert_eq!(team_of(&gates, &stranger), Err(VerifyError::UnknownSubject));
    // The pod's default API token: real and cluster-signed, for the API server's audience.
    let default_token = kubernetes_token(issuer(), TEAM_A_SA, &[CLUSTER_ISSUER]);
    assert_eq!(
        team_of(&gates, &default_token),
        Err(VerifyError::AudienceMismatch)
    );
    // The right shape, signed by a key the keys file does not hold.
    let impostor = cluster_issuer();
    let forged = kubernetes_token(&impostor, TEAM_A_SA, &[AUDIENCE]);
    assert_eq!(team_of(&gates, &forged), Err(VerifyError::UnknownKeyId));
}

#[tokio::test]
async fn rotating_a_key_is_a_new_keys_file_and_a_restart() {
    let old = issuer();
    let new = cluster_issuer();
    assert_ne!(old.key_id(), new.key_id());
    let old_token = kubernetes_token(old, TEAM_A_SA, &[AUDIENCE]);
    let new_token = kubernetes_token(&new, TEAM_A_SA, &[AUDIENCE]);

    // Both keys published: tokens signed under either verify.
    let files = Files::new("rotation", &key_set(&[old, &new]), "http://127.0.0.1:9/mcp");
    let both = gates(&files).await;
    assert_eq!(team_of(&both, &old_token), Ok("team-a".to_owned()));
    assert_eq!(team_of(&both, &new_token), Ok("team-a".to_owned()));

    // The old key dropped from the file. A gateway started before still holds both keys:
    // the file is read at boot and nothing is fetched or watched.
    files.write("jwks.json", &key_set(&[&new]));
    assert_eq!(team_of(&both, &old_token), Ok("team-a".to_owned()));

    // Restarted, it refuses the old key's tokens and accepts the new key's.
    let restarted = gates(&files).await;
    assert_eq!(
        team_of(&restarted, &old_token),
        Err(VerifyError::UnknownKeyId)
    );
    assert_eq!(team_of(&restarted, &new_token), Ok("team-a".to_owned()));
}

#[tokio::test]
async fn identity_the_identity_crate_refuses_stops_the_gateway() {
    let files = Files::new(
        "identity-refused",
        &issuer().jwks_document(),
        "http://127.0.0.1:9/mcp",
    );
    let refused = |files: &Files| {
        let deployment = files.load();
        async move {
            gateway::start::prepare(deployment, Arc::new(SystemClock))
                .await
                .unwrap_err()
                .to_string()
        }
    };
    // An empty team manifest.
    files.write("teams.toml", "[subjects]\n");
    assert!(refused(&files).await.contains("has no subjects"));
    files.write(
        "teams.toml",
        &format!("[subjects]\n\"{TEAM_A_SA}\" = \"team-a\"\n"),
    );
    // No keys.
    files.write("jwks.json", r#"{"keys": []}"#);
    assert!(refused(&files).await.contains("has no keys"));
    // Keys for another algorithm.
    let ec = LocalIssuer::new(CLUSTER_ISSUER, gateway_identity::SigningAlgorithm::Es256).unwrap();
    files.write("jwks.json", &ec.jwks_document());
    assert!(
        refused(&files)
            .await
            .contains("cannot verify RS256 signatures")
    );
}
