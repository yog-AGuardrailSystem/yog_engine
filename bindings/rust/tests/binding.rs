use yog::{Decision, Limits, Obligation, ObligationArg, Yog};

const POLICY: &str = "\
fact role(alice, admin)
fact member(bob, core)
fact team_resource(core, db)
allow can_access(User, Resource):
    role(User, admin)
allow can_access(User, Resource):
    member(User, Team)
    team_resource(Team, Resource)
";

#[test]
fn allows_admin_and_member() {
    let policy = Yog::compile(POLICY).expect("compile");
    assert_eq!(
        policy.check("alice", "can_access", "db").unwrap(),
        Decision::Allow
    );
    assert_eq!(
        policy.check("bob", "can_access", "db").unwrap(),
        Decision::Allow
    );
}

#[test]
fn denies_unknown_subject() {
    let policy = Yog::compile(POLICY).expect("compile");
    assert_eq!(
        policy.check("nobody", "can_access", "db").unwrap(),
        Decision::Deny
    );
}

#[test]
fn reports_compile_error() {
    let error = Yog::compile("allow broken(:\n").expect_err("must fail");
    assert!(error.line > 0);
    assert!(!error.message.is_empty());
}

#[test]
fn limits_round_trip_and_fail_closed() {
    let mut policy = Yog::compile(POLICY).expect("compile");
    policy.set_limits(Limits {
        max_steps: 1_000_000,
        max_depth: 8,
        ..Limits::default()
    });
    assert_eq!(policy.limits().max_depth, 8);
    policy.set_limits(Limits {
        max_steps: 1,
        max_depth: 8,
        ..Limits::default()
    });
    assert!(policy.check("nobody", "can_access", "db").is_err());
}

#[test]
fn context_does_not_leak() {
    let policy = Yog::compile(
        "fact role(carol, guest)\nallow can_access(User, Resource):\n    role(User, admin)\n",
    )
    .expect("compile");
    assert_eq!(
        policy
            .check_with_context(
                "carol",
                "can_access",
                "db",
                Some("fact role(carol, admin)"),
                false
            )
            .unwrap()
            .0,
        Decision::Allow
    );
    assert_eq!(
        policy.check("carol", "can_access", "db").unwrap(),
        Decision::Deny
    );
}

#[test]
fn policy_is_shareable_across_threads() {
    use std::sync::Arc;
    let policy = Arc::new(Yog::compile(POLICY).expect("compile"));
    let mut handles = Vec::new();
    for _ in 0..4 {
        let policy = Arc::clone(&policy);
        handles.push(std::thread::spawn(move || {
            for _ in 0..500 {
                assert_eq!(
                    policy.check("alice", "can_access", "db").unwrap(),
                    Decision::Allow
                );
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn library_version_matches_crate_version() {
    assert_eq!(yog::library_version(), yog::VERSION);
}

#[test]
fn resource_limits_default_and_fail_closed() {
    let mut policy = Yog::compile(POLICY).expect("compile");
    let defaults = policy.limits();
    assert_eq!(defaults.max_solutions, 100_000);
    assert_eq!(defaults.max_millis, 10_000);
    assert_eq!(defaults.max_memory, 64 * 1024 * 1024);
    policy.set_limits(Limits {
        max_memory: 1,
        ..Limits::default()
    });
    assert_eq!(policy.limits().max_memory, 1);
    assert_eq!(policy.limits().max_steps, defaults.max_steps);
    assert!(policy.check("bob", "can_access", "db").is_err());
}

const V2: &str = "version 2
input arg(text, any)
input env(text, any)
deny act(U, R):
    arg(\"sql\", Q)
    matches(Q, \"(?i)drop table\")
require_approval act(U, R):
    env(\"stage\", \"prod\")
    obligation audit(\"prod\", R)
allow act(U, R):
    arg(\"n\", N)
    N > 3
    obligation audit(\"allowed\", R)
    obligation limit(U, N, true)
";

#[test]
fn outcomes_and_obligations_round_trip() {
    let policy = Yog::compile(V2).expect("compile");
    assert_eq!(policy.policy_version(), 2);
    let allow = policy
        .check_json(r#"{"actor":"bot","action":"act","resource":"db","args":{"n":7}}"#, false)
        .expect("check");
    assert_eq!(allow.decision, Decision::Allow);
    assert_eq!(
        allow.obligations,
        vec![
            Obligation {
                name: "audit".into(),
                args: vec![ObligationArg::Text("allowed".into()), ObligationArg::Text("db".into())],
            },
            Obligation {
                name: "limit".into(),
                args: vec![
                    ObligationArg::Text("bot".into()),
                    ObligationArg::Integer(7),
                    ObligationArg::Boolean(true),
                ],
            },
        ]
    );
    let approval = policy
        .check_json(r#"{"actor":"bot","action":"act","resource":"db","env":{"stage":"prod"}}"#, false)
        .expect("check");
    assert_eq!(approval.decision, Decision::RequireApproval);
    let denied = policy
        .check_json(r#"{"actor":"bot","action":"act","resource":"db","args":{"sql":"x DROP TABLE y","n":9}}"#, false)
        .expect("check");
    assert_eq!(denied.decision, Decision::Deny);
    assert!(denied.obligations.is_empty());
}

#[test]
fn malformed_json_requests_are_errors_not_allows() {
    let policy = Yog::compile(V2).expect("compile");
    for bad in [
        "not json",
        r#"{"actor":"bot"}"#,
        r#"{"actor":"a","action":"act","resource":"r","bogus":1}"#,
        r#"{"actor":"a","action":"act","resource":"r","args":{"x":1.5}}"#,
    ] {
        assert!(policy.check_json(bad, false).is_err(), "{bad}");
    }
}
