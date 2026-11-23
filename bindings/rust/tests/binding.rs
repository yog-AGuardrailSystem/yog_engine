use yog::{Decision, Limits, Yog};

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
