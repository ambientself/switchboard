//! The gateway's whole path with no HTTP: verifier, decision, audit begin, run, audit finish,
//! using only the fakes and the fixture. This is the path issue 26 puts behind an endpoint, so
//! each behaviour the design promises is shown here, in milliseconds, by telling a fake to fail.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::pin::pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use gateway_core::audit::{
    self, Answer, Begun, Completion, DecisionKind, Outcome, RequestMetadata,
};
use gateway_core::{
    CallContext, Classification, IDENTITY_FAILURE, ReasonKind, RequestedTool, decide,
};
use gateway_identity::{Identity, Verification, VerifyError};
use gateway_testkit::{
    Caller, FakeCredentialSource, Fixture, FixtureConnector, InMemoryAuditStore, READ_TOOL,
    SCOPE_REFUSAL, SCOPED_READ_TOOL, SURFACE_ALL, SURFACE_READ, SteppableClock, TEAM_A_DOCUMENT,
    TEAM_B_DOCUMENT, WRITE_TOOL, block_on, poll_once,
};
use serde_json::{Value, json};

const AUDIT_FAILURE: &str = "The gateway could not record this call in its audit log, so it was refused and nothing ran. Try again later.";

/// What the gateway would answer.
#[derive(Debug)]
enum Response {
    /// Step 1 refused the caller. Nothing else ran.
    Unverified {
        sentence: &'static str,
        detail: VerifyError,
    },
    /// The audit row could not be written, so the call was refused whatever the decision was.
    AuditFailed(&'static str),
    /// Denied, with the sentence the row also holds.
    Denied {
        sentence: String,
        reason: ReasonKind,
    },
    /// The call ran. `row_completed` is whether the audit row was finished.
    Answered { answer: Answer, row_completed: bool },
}

struct Gateway {
    fixture: Fixture,
    identity: Identity,
    store: InMemoryAuditStore,
    credentials: Arc<FakeCredentialSource>,
    connector: FixtureConnector,
    clock: SteppableClock,
}

impl Gateway {
    fn new() -> Self {
        let fixture = Fixture::new().unwrap();
        let credentials = Arc::new(FakeCredentialSource::new());
        let connector = FixtureConnector::new(credentials.clone());
        // The connector's clock is the verifier's clock, so a call's latency is measured on
        // the same time the tokens are checked against.
        let clock = fixture.clock.clone();
        Self {
            identity: fixture.identity().unwrap(),
            store: InMemoryAuditStore::new(),
            fixture,
            credentials,
            connector,
            clock,
        }
    }

    fn token(&self, caller: Caller) -> String {
        self.fixture.token(caller)
    }

    /// Steps 1 to 9 of the request path for one `tools/call`.
    async fn handle(
        &self,
        token: Option<&str>,
        surface: &str,
        tool: &str,
        arguments: Value,
    ) -> Response {
        let principal = match self.identity.check(token) {
            Verification::Proved(principal) => principal,
            Verification::Failed(failure) => {
                return Response::Unverified {
                    sentence: failure.outward(),
                    detail: failure.detail().clone(),
                };
            }
            Verification::Disabled => panic!("this gateway is configured to check"),
        };
        let call = CallContext {
            resources: FixtureConnector::resources_of(tool, &arguments),
            caller: Fixture::context_for(principal, surface),
            tool: RequestedTool::new(tool),
        };
        let decision = decide(&self.fixture.policy, &call);
        let begun = match audit::begin(&self.store, decision, arguments, RequestMetadata::default())
            .await
        {
            Ok(begun) => begun,
            Err(failure) => return Response::AuditFailed(failure.sentence()),
        };
        match begun {
            Begun::Denied(refusal) => Response::Denied {
                sentence: refusal.sentence().to_owned(),
                reason: refusal.reason().kind(),
            },
            Begun::Allowed(guard) => {
                let started = self.clock.unix_millis();
                let ran = audit::run(&self.connector, guard).await;
                let latency = self.clock.unix_millis() - started;
                let finished = audit::finish(&self.store, ran, latency).await;
                Response::Answered {
                    answer: finished.answer().clone(),
                    row_completed: finished.failure().is_none(),
                }
            }
        }
    }

    fn call(&self, caller: Caller, surface: &str, tool: &str, arguments: Value) -> Response {
        let token = self.token(caller);
        block_on(self.handle(Some(&token), surface, tool, arguments))
    }

    /// Nothing reached the connector or the credential source.
    fn assert_nothing_ran(&self) {
        assert!(
            self.connector.received().is_empty(),
            "the connector received a call"
        );
        assert!(self.connector.writes().is_empty(), "a write happened");
        assert!(
            self.credentials.requests().is_empty(),
            "a credential was requested"
        );
    }
}

fn own(caller: Caller) -> Value {
    json!({"document": caller.own_document()})
}

#[test]
fn an_allowed_read_returns_the_echo_and_completes_its_row() {
    let gateway = Gateway::new();
    gateway
        .connector
        .take_time(gateway.clock.clone(), Duration::from_millis(25));
    let arguments = json!({"document": TEAM_A_DOCUMENT, "page": 2});

    let Response::Answered {
        answer,
        row_completed,
    } = gateway.call(Caller::TeamA, SURFACE_ALL, READ_TOOL, arguments.clone())
    else {
        panic!("not answered")
    };
    assert!(row_completed);
    assert_eq!(
        answer,
        Answer::Ok(json!({
            "tool": READ_TOOL,
            "echo": arguments,
            "credential": "fake-credential-for-fixture-team-a-1",
        }))
    );

    let rows = gateway.store.rows();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!((row.reason, row.sentence.as_deref()), (None, None));
    assert_eq!(row.tool, READ_TOOL);
    assert_eq!(row.connector.as_ref().map(|c| c.as_str()), Some("fixture"));
    assert_eq!(row.classification, Some(Classification::Read));
    assert_eq!(row.surface.as_str(), SURFACE_ALL);
    assert_eq!(row.policy_revision.as_str(), "fixture-1");
    assert_eq!(
        row.proved_principal.get(),
        gateway.fixture.principal(Caller::TeamA).unwrap().get()
    );
    assert_eq!(
        row.completion,
        Some(Completion {
            outcome: Outcome::Ok,
            latency_ms: 25
        })
    );

    // The credential was the caller's own team's, asked for once, for the proved principal.
    let requests = gateway.credentials.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].team.as_ref().map(|t| t.as_str()),
        Some("team-a")
    );
    assert_eq!(gateway.connector.received().len(), 1);
}

#[test]
fn each_caller_runs_under_its_own_credential() {
    let gateway = Gateway::new();
    for caller in [Caller::TeamA, Caller::TeamB, Caller::UserInGroupG] {
        let surface = if caller == Caller::UserInGroupG {
            SURFACE_READ
        } else {
            SURFACE_ALL
        };
        assert!(matches!(
            gateway.call(caller, surface, READ_TOOL, own(caller)),
            Response::Answered {
                answer: Answer::Ok(_),
                ..
            }
        ));
    }
    let labels: Vec<_> = gateway
        .credentials
        .requests()
        .into_iter()
        .map(|r| r.issued.unwrap())
        .collect();
    assert_eq!(
        labels,
        [
            "fake-credential-for-fixture-team-a-1",
            "fake-credential-for-fixture-team-b-2",
            "fake-credential-for-fixture-user-user-1@fixture.test-3",
        ]
    );
}

#[test]
fn a_denied_call_never_reaches_the_connector_and_its_row_is_the_denial() {
    use ReasonKind::*;
    let gateway = Gateway::new();
    let table: [(Caller, &str, &str, Value, ReasonKind); 6] = [
        (
            Caller::TeamB,
            SURFACE_ALL,
            WRITE_TOOL,
            own(Caller::TeamB),
            ClassificationNotPermitted,
        ),
        (
            Caller::TeamA,
            SURFACE_READ,
            WRITE_TOOL,
            own(Caller::TeamA),
            ToolNotOnSurface,
        ),
        (
            Caller::UserInGroupG,
            SURFACE_ALL,
            READ_TOOL,
            own(Caller::UserInGroupG),
            SurfaceNotPermitted,
        ),
        (
            Caller::TeamA,
            SURFACE_ALL,
            "fixture__no_such_tool",
            own(Caller::TeamA),
            UnknownTool,
        ),
        (
            Caller::TeamB,
            SURFACE_ALL,
            READ_TOOL,
            json!({"document": TEAM_A_DOCUMENT}),
            ResourceOutsideLimit,
        ),
        (
            Caller::TeamA,
            SURFACE_ALL,
            WRITE_TOOL,
            json!({}),
            ResourceOutsideLimit,
        ),
    ];
    for (position, (caller, surface, tool, arguments, expected)) in table.into_iter().enumerate() {
        let Response::Denied { sentence, reason } = gateway.call(caller, surface, tool, arguments)
        else {
            panic!("{caller:?} {tool} was not denied")
        };
        assert_eq!(reason, expected, "{caller:?} {surface} {tool}");
        let row = gateway.store.row(position).expect("the denial has a row");
        assert_eq!(row.decision, DecisionKind::Deny);
        assert_eq!(row.reason, Some(expected));
        assert_eq!(
            row.sentence.as_deref(),
            Some(sentence.as_str()),
            "the row and the answer say the same"
        );
        assert_eq!(row.completion, None, "a denial's row is complete as begun");
        gateway.assert_nothing_ran();
    }
    assert_eq!(gateway.store.rows().len(), 6, "one row per denied call");
    assert_eq!(gateway.store.finish_attempts(), 0);
}

#[test]
fn a_denied_write_does_not_write_and_the_same_write_allowed_does() {
    let gateway = Gateway::new();
    let write = |caller| gateway.call(caller, SURFACE_ALL, WRITE_TOOL, own(caller));
    assert!(matches!(write(Caller::TeamB), Response::Denied { .. }));
    assert!(gateway.connector.writes().is_empty());
    assert!(matches!(
        write(Caller::TeamA),
        Response::Answered {
            answer: Answer::Ok(_),
            ..
        }
    ));
    assert_eq!(gateway.connector.writes().len(), 1);
}

#[test]
fn when_the_audit_row_cannot_be_begun_the_call_is_refused_and_nothing_runs() {
    let gateway = Gateway::new();
    gateway.store.fail_next_begin();
    let response = gateway.call(Caller::TeamA, SURFACE_ALL, WRITE_TOOL, own(Caller::TeamA));
    assert!(
        matches!(response, Response::AuditFailed(AUDIT_FAILURE)),
        "{response:?}"
    );
    assert!(gateway.store.rows().is_empty());
    gateway.assert_nothing_ran();

    // A denial is refused the same way: with no row, nothing is returned but the audit failure.
    gateway.store.fail_next_begin();
    let response = gateway.call(Caller::TeamB, SURFACE_ALL, WRITE_TOOL, own(Caller::TeamB));
    assert!(
        matches!(response, Response::AuditFailed(AUDIT_FAILURE)),
        "{response:?}"
    );
    assert!(gateway.store.rows().is_empty());

    // And when the store is back, the same call goes through.
    assert!(matches!(
        gateway.call(Caller::TeamA, SURFACE_ALL, WRITE_TOOL, own(Caller::TeamA)),
        Response::Answered {
            answer: Answer::Ok(_),
            row_completed: true
        }
    ));
    assert_eq!(gateway.connector.writes().len(), 1);
}

#[test]
fn a_store_that_is_down_refuses_every_call_while_it_is_down() {
    let gateway = Gateway::new();
    gateway.store.fail_all_begins();
    for _ in 0..3 {
        assert!(matches!(
            gateway.call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA)),
            Response::AuditFailed(_)
        ));
    }
    gateway.assert_nothing_ran();
}

#[test]
fn a_failure_to_finish_the_row_does_not_undo_a_success() {
    let gateway = Gateway::new();
    gateway.store.fail_next_finish();
    let Response::Answered {
        answer,
        row_completed,
    } = gateway.call(Caller::TeamA, SURFACE_ALL, WRITE_TOOL, own(Caller::TeamA))
    else {
        panic!("not answered")
    };
    assert!(
        matches!(answer, Answer::Ok(_)),
        "the result of a write that happened is still returned: {answer:?}"
    );
    assert!(!row_completed, "and the failure is reported");
    assert_eq!(gateway.connector.writes().len(), 1, "the write stands");
    let row = gateway.store.row(0).unwrap();
    assert_eq!(row.decision, DecisionKind::Allow);
    assert_eq!(
        row.completion, None,
        "the empty outcome is the evidence that the gateway never learned what happened"
    );
}

#[test]
fn a_scope_refusal_is_the_outcome_refused_with_one_sentence_in_the_row_and_the_answer() {
    let gateway = Gateway::new();
    // Team A asks the tool that checks its own scope for team B's document. The decision
    // function cannot see that, so it allows the call, and the connector refuses it.
    let response = gateway.call(
        Caller::TeamA,
        SURFACE_ALL,
        SCOPED_READ_TOOL,
        json!({"document": TEAM_B_DOCUMENT}),
    );
    let Response::Answered {
        answer: Answer::Refused(sentence),
        row_completed: true,
    } = response
    else {
        panic!("{response:?}")
    };
    assert_eq!(sentence, SCOPE_REFUSAL);
    let row = gateway.store.row(0).unwrap();
    assert_eq!(
        row.decision,
        DecisionKind::Allow,
        "the decision function allowed it"
    );
    assert_eq!(
        row.completion,
        Some(Completion {
            outcome: Outcome::Refused {
                sentence: sentence.clone()
            },
            latency_ms: 0
        })
    );
    assert_eq!(gateway.connector.received().len(), 1, "it ran, and refused");
}

#[test]
fn a_scope_refusal_that_cannot_be_recorded_is_not_answered_with_its_sentence() {
    let gateway = Gateway::new();
    gateway.store.fail_next_finish();
    let response = gateway.call(
        Caller::TeamA,
        SURFACE_ALL,
        SCOPED_READ_TOOL,
        json!({"document": "restricted-notes"}),
    );
    let Response::Answered {
        answer,
        row_completed: false,
    } = response
    else {
        panic!("{response:?}")
    };
    assert_eq!(
        answer,
        Answer::AuditFailed {
            sentence: AUDIT_FAILURE
        }
    );
    assert_eq!(gateway.store.row(0).unwrap().completion, None);
}

#[test]
fn a_connector_error_and_a_refused_credential_are_recorded_as_errors() {
    let gateway = Gateway::new();
    gateway.connector.fail_next();
    let response = gateway.call(Caller::TeamA, SURFACE_ALL, READ_TOOL, own(Caller::TeamA));
    assert!(
        matches!(
            response,
            Response::Answered {
                answer: Answer::Error(_),
                row_completed: true
            }
        ),
        "{response:?}"
    );
    assert_eq!(
        gateway.store.row(0).unwrap().completion.map(|c| c.outcome),
        Some(Outcome::Error)
    );

    gateway.credentials.refuse_next();
    let response = gateway.call(Caller::TeamA, SURFACE_ALL, WRITE_TOOL, own(Caller::TeamA));
    assert!(
        matches!(
            response,
            Response::Answered {
                answer: Answer::Error(_),
                row_completed: true
            }
        ),
        "{response:?}"
    );
    assert_eq!(
        gateway.store.row(1).unwrap().completion.map(|c| c.outcome),
        Some(Outcome::Error)
    );
    assert!(
        gateway.connector.writes().is_empty(),
        "no credential, no write"
    );
}

#[test]
fn a_caller_who_cannot_be_verified_gets_the_one_sentence_and_nothing_runs() {
    let gateway = Gateway::new();
    let good = gateway.token(Caller::TeamA);
    let expired = {
        let token = gateway.token(Caller::TeamA);
        gateway.clock.advance(Duration::from_secs(7200));
        token
    };
    let wrong_audience = gateway
        .fixture
        .workload_issuer
        .workload_token(
            gateway_testkit::TEAM_A_SUBJECT,
            "another-gateway",
            gateway_identity::Clock::now(&gateway.clock),
        )
        .build();
    let unknown_subject = gateway
        .fixture
        .workload_issuer
        .workload_token(
            "system:serviceaccount:team-c:sandbox",
            gateway_testkit::AUDIENCE,
            gateway_identity::Clock::now(&gateway.clock),
        )
        .build();
    let attempts: [(Option<&str>, VerifyError); 5] = [
        (None, VerifyError::MissingToken),
        (Some("not a token"), VerifyError::MalformedToken),
        (Some(&expired), VerifyError::Expired),
        (Some(&wrong_audience), VerifyError::AudienceMismatch),
        (Some(&unknown_subject), VerifyError::UnknownSubject),
    ];
    for (token, expected) in attempts {
        let response = block_on(gateway.handle(token, SURFACE_ALL, READ_TOOL, own(Caller::TeamA)));
        let Response::Unverified { sentence, detail } = response else {
            panic!("{response:?}")
        };
        assert_eq!(sentence, IDENTITY_FAILURE, "{expected:?}");
        assert_eq!(detail, expected, "the cause is kept for the log");
    }
    // The time moved, so the token that was good is now expired too.
    assert!(matches!(
        block_on(gateway.handle(Some(&good), SURFACE_ALL, READ_TOOL, own(Caller::TeamA))),
        Response::Unverified {
            detail: VerifyError::Expired,
            ..
        }
    ));
    gateway.assert_nothing_ran();
    // No principal was proved, so there is nothing to write a row about (see the PR).
    assert!(gateway.store.rows().is_empty());
}

#[test]
fn the_audit_row_is_written_before_the_tool_runs_and_finished_before_the_answer() {
    let gateway = Gateway::new();
    let token = gateway.token(Caller::TeamA);

    // A connector that hangs: the row already exists, with an empty outcome.
    let gate = gateway.connector.hang_next();
    let mut call = pin!(gateway.handle(Some(&token), SURFACE_ALL, WRITE_TOOL, own(Caller::TeamA)));
    assert!(poll_once(call.as_mut()).is_pending());
    assert_eq!(gateway.connector.received().len(), 1);
    assert!(gateway.connector.writes().is_empty());
    let row = gateway
        .store
        .row(0)
        .expect("the row is written before the tool runs");
    assert_eq!((row.decision, row.completion), (DecisionKind::Allow, None));
    gate.open();
    assert!(matches!(
        poll_once(call.as_mut()),
        Poll::Ready(Response::Answered {
            answer: Answer::Ok(_),
            row_completed: true
        })
    ));

    // A store that is slow to finish: the tool has run, and the answer waits for the row.
    let gate = gateway.store.hold_finishes();
    let mut call = pin!(gateway.handle(Some(&token), SURFACE_ALL, WRITE_TOOL, own(Caller::TeamA)));
    assert!(poll_once(call.as_mut()).is_pending());
    assert_eq!(
        gateway.connector.writes().len(),
        2,
        "the write has happened"
    );
    assert_eq!(gateway.store.row(1).unwrap().completion, None);
    gate.open();
    assert!(matches!(
        poll_once(call.as_mut()),
        Poll::Ready(Response::Answered {
            row_completed: true,
            ..
        })
    ));
    assert!(gateway.store.row(1).unwrap().completion.is_some());

    // A store that is slow to begin: nothing runs, and nothing is answered, until the row is
    // written.
    let gate = gateway.store.hold_begins();
    let mut call = pin!(gateway.handle(Some(&token), SURFACE_ALL, WRITE_TOOL, own(Caller::TeamA)));
    assert!(poll_once(call.as_mut()).is_pending());
    assert_eq!(gateway.store.rows().len(), 2);
    assert_eq!(
        gateway.connector.received().len(),
        2,
        "no third call has arrived"
    );
    gate.open();
    assert!(poll_once(call.as_mut()).is_ready());
    assert_eq!(gateway.store.rows().len(), 3);
}

#[test]
fn the_two_teams_resources_are_separate_end_to_end() {
    let gateway = Gateway::new();
    assert!(matches!(
        gateway.call(
            Caller::TeamB,
            SURFACE_ALL,
            READ_TOOL,
            json!({"document": TEAM_B_DOCUMENT})
        ),
        Response::Answered {
            answer: Answer::Ok(_),
            ..
        }
    ));
    assert!(matches!(
        gateway.call(
            Caller::TeamB,
            SURFACE_ALL,
            READ_TOOL,
            json!({"document": TEAM_A_DOCUMENT})
        ),
        Response::Denied {
            reason: ReasonKind::ResourceOutsideLimit,
            ..
        }
    ));
}
