//! `tools/list` end to end: each caller is shown only the tools it may call, in both eras.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use gateway_dev::{Options, start_fixture_gateway, start_fixture_gateway_with};
use gateway_mcp::{Era, LIST_TTL_MS};
use gateway_testkit::{
    Caller, DRAFT_TOOL, READ_TOOL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, WRITE_TOOL,
};
use serde_json::json;
use support::{call, document, list};

const ERAS: [Era; 2] = [Era::Legacy, Era::Modern];

fn names(tools: &[&str]) -> Vec<String> {
    tools.iter().map(|tool| (*tool).to_owned()).collect()
}

#[tokio::test]
async fn a_caller_is_listed_only_the_tools_it_may_call() {
    let gateway = start_fixture_gateway().await.unwrap();
    let team_a = gateway.token(Caller::TeamA);
    let team_b = gateway.token(Caller::TeamB);
    let user = gateway.token(Caller::UserInGroupG);
    for era in ERAS {
        // Team A's profile reads and proposes. No profile may write, so the write tool is
        // left out for every caller.
        let (listed, _) = list(&gateway, Some(&team_a), era, SURFACE_ALL).await;
        assert_eq!(
            listed,
            names(&[DRAFT_TOOL, READ_TOOL, SCOPED_READ_TOOL]),
            "{era}"
        );
        // Team B's profile only reads, so the draft tool is left out too.
        let (listed, _) = list(&gateway, Some(&team_b), era, SURFACE_ALL).await;
        assert_eq!(listed, names(&[READ_TOOL, SCOPED_READ_TOOL]), "{era}");
        // The user may not use that surface at all.
        let (listed, _) = list(&gateway, Some(&user), era, SURFACE_ALL).await;
        assert_eq!(listed, Vec::<String>::new(), "{era}");
        // It may use the read surface.
        let (listed, _) = list(&gateway, Some(&user), era, SURFACE_READ).await;
        assert_eq!(listed, names(&[READ_TOOL, SCOPED_READ_TOOL]), "{era}");
        // A surface nobody configured serves nobody anything.
        let (listed, _) = list(&gateway, Some(&team_b), era, "no-such-surface").await;
        assert_eq!(listed, Vec::<String>::new(), "{era}");
    }
    // Each list writes one row of kind list, never a call row, and runs nothing.
    assert_eq!(gateway.store().list_rows().len(), 10);
    assert_eq!(gateway.store().begin_attempts(), 0);
    assert_eq!(gateway.connector().received(), Vec::new());
}

#[tokio::test]
async fn every_listed_tool_can_be_called_and_an_unlisted_one_on_the_surface_cannot() {
    let gateway = start_fixture_gateway().await.unwrap();
    let mut ran = 0;
    for caller in [Caller::TeamA, Caller::TeamB] {
        let token = gateway.token(caller);
        let (listed, _) = list(&gateway, Some(&token), Era::Modern, SURFACE_ALL).await;
        let own = document(caller.own_document());
        for tool in [READ_TOOL, DRAFT_TOOL, WRITE_TOOL, SCOPED_READ_TOOL] {
            let answer = call(
                &gateway,
                caller,
                Era::Modern,
                SURFACE_ALL,
                tool,
                own.clone(),
            )
            .await;
            if listed.contains(&tool.to_owned()) {
                let (is_error, result) = answer.tool_result();
                assert!(!is_error, "{caller:?} {tool}: {result}");
                ran += 1;
            } else {
                answer.denial();
            }
        }
        assert!(!listed.contains(&WRITE_TOOL.to_owned()), "{caller:?}");
    }
    assert_eq!(ran, 5, "team A's three tools and team B's two");
    assert_eq!(gateway.connector().received().len(), ran);
    assert_eq!(
        gateway.connector().writes().len(),
        1,
        "team A's one proposal"
    );
}

#[tokio::test]
async fn the_list_is_the_same_in_both_eras_and_private_to_the_caller_in_the_modern_one() {
    let gateway = start_fixture_gateway().await.unwrap();
    for caller in [Caller::TeamA, Caller::TeamB, Caller::UserInGroupG] {
        let token = gateway.token(caller);
        for surface in [SURFACE_READ, SURFACE_ALL] {
            let (_, legacy) = list(&gateway, Some(&token), Era::Legacy, surface).await;
            let (_, modern) = list(&gateway, Some(&token), Era::Modern, surface).await;
            assert_eq!(legacy["tools"], modern["tools"], "{caller:?} on {surface}");

            // The list depends on who asks, so a shared cache must not keep it.
            assert_eq!(modern["cacheScope"], json!("private"));
            assert_eq!(modern["ttlMs"], json!(LIST_TTL_MS));
            assert_eq!(modern["resultType"], json!("complete"));
            assert_eq!(modern.get("nextCursor"), None);
            assert_eq!(legacy.get("cacheScope"), None);
            assert_eq!(legacy.get("resultType"), None);
        }
    }
}

#[tokio::test]
async fn each_listed_tool_has_its_definition_and_says_whether_it_only_reads() {
    let gateway = start_fixture_gateway().await.unwrap();
    let catalog = gateway_dev::catalog_data();
    // Team A on the surface that serves everything is listed the draft tool too, which does
    // not only read.
    let token = gateway.token(Caller::TeamA);
    let (listed, result) = list(&gateway, Some(&token), Era::Modern, SURFACE_ALL).await;
    assert!(listed.contains(&DRAFT_TOOL.to_owned()), "{listed:?}");
    for tool in result["tools"].as_array().unwrap() {
        let name = tool["name"].as_str().unwrap();
        let definition = catalog
            .as_array()
            .unwrap()
            .iter()
            .find(|definition| definition["name"] == json!(name))
            .unwrap();
        assert_eq!(tool["description"], definition["description"], "{name}");
        assert_eq!(tool["title"], definition["title"], "{name}");
        assert_eq!(tool["inputSchema"], definition["input_schema"], "{name}");
        assert_eq!(
            tool["annotations"]["readOnlyHint"],
            json!(name != DRAFT_TOOL),
            "{name}"
        );
    }
}

#[tokio::test]
async fn with_identity_disabled_nothing_is_listed() {
    let gateway = start_fixture_gateway_with(Options::new().identity_disabled())
        .await
        .unwrap();
    for era in ERAS {
        for surface in [SURFACE_READ, SURFACE_ALL] {
            let (listed, _) = list(&gateway, None, era, surface).await;
            assert_eq!(listed, Vec::<String>::new(), "{era} on {surface}");
        }
    }
    // A token changes nothing: no one checks it.
    let token = gateway.token(Caller::TeamA);
    let (listed, _) = list(&gateway, Some(&token), Era::Legacy, SURFACE_READ).await;
    assert_eq!(listed, Vec::<String>::new());
}
