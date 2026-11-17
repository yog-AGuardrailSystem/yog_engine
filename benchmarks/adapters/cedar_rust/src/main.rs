//! In-process Cedar harness for the fair cross-engine comparison.
//!
//! It loads a Cedar policy set and entities once, then evaluates every request
//! in a tab-separated file.  This mirrors the Rust YOG binding: same language,
//! same process, same measurement loop.  The Cedar CLI is *not* used here, so
//! process startup and per-invocation entity loading are excluded.
//!
//! Usage:
//!   cedar-bench --policy P --entities E --requests R
//!               [--iterations N] [--warmup N] [--mode load|warm]

use std::env;
use std::fs;
use std::process;
use std::str::FromStr;
use std::time::Instant;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request,
};

struct Args {
    policy: String,
    entities: String,
    requests: String,
    iterations: usize,
    warmup: usize,
    mode: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        policy: String::new(),
        entities: String::new(),
        requests: String::new(),
        iterations: 5000,
        warmup: 100,
        mode: "warm".to_string(),
    };
    let mut items = env::args().skip(1);
    while let Some(flag) = items.next() {
        let value = items.next().unwrap_or_else(|| {
            eprintln!("missing value for {flag}");
            process::exit(2);
        });
        match flag.as_str() {
            "--policy" => args.policy = value,
            "--entities" => args.entities = value,
            "--requests" => args.requests = value,
            "--iterations" => args.iterations = value.parse().expect("integer"),
            "--warmup" => args.warmup = value.parse().expect("integer"),
            "--mode" => args.mode = value,
            other => {
                eprintln!("unknown argument: {other}");
                process::exit(2);
            }
        }
    }
    if args.policy.is_empty() || args.entities.is_empty() {
        eprintln!("--policy and --entities are required");
        process::exit(2);
    }
    args
}

fn main() {
    let args = parse_args();

    let policy_text = fs::read_to_string(&args.policy).expect("read policy");
    let entities_text = fs::read_to_string(&args.entities).expect("read entities");

    let policy_started = Instant::now();
    let policies = PolicySet::from_str(&policy_text).unwrap_or_else(|error| {
        eprintln!("policy error: {error}");
        process::exit(1);
    });
    let policy_ns = policy_started.elapsed().as_nanos();

    let entities_started = Instant::now();
    let entities = Entities::from_json_str(&entities_text, None).unwrap_or_else(|error| {
        eprintln!("entities error: {error}");
        process::exit(1);
    });
    let entities_ns = entities_started.elapsed().as_nanos();

    if args.mode == "load" {
        println!(
            "{{\"mode\":\"load\",\"policy_ns\":{},\"entities_ns\":{},\"load_ns\":{},\"policies\":{},\"entities\":{}}}",
            policy_ns,
            entities_ns,
            policy_ns + entities_ns,
            policies.policies().count(),
            entities.iter().count()
        );
        return;
    }

    let text = fs::read_to_string(&args.requests).expect("read requests");
    let authorizer = Authorizer::new();

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 4 {
            eprintln!("malformed request line: {line}");
            process::exit(1);
        }
        let (label, actor, action, resource) = (fields[0], fields[1], fields[2], fields[3]);

        let principal: EntityUid = format!("User::\"{actor}\"").parse().unwrap_or_else(|error| {
            eprintln!("principal error: {error}");
            process::exit(1);
        });
        let action: EntityUid = format!("Action::\"{action}\"").parse().unwrap_or_else(|error| {
            eprintln!("action error: {error}");
            process::exit(1);
        });
        let resource: EntityUid = format!("Resource::\"{resource}\"")
            .parse()
            .unwrap_or_else(|error| {
                eprintln!("resource error: {error}");
                process::exit(1);
            });
        let request = Request::new(principal, action, resource, Context::empty(), None)
            .unwrap_or_else(|error| {
                eprintln!("request error: {error}");
                process::exit(1);
            });

        let mut decision = Decision::Deny;
        for _ in 0..args.warmup {
            decision = authorizer
                .is_authorized(&request, &policies, &entities)
                .decision();
        }

        let mut samples = Vec::with_capacity(args.iterations);
        for _ in 0..args.iterations {
            let started = Instant::now();
            decision = authorizer
                .is_authorized(&request, &policies, &entities)
                .decision();
            samples.push(started.elapsed().as_nanos());
        }

        let values = samples
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let decision = match decision {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        };
        println!(
            "{{\"label\":\"{}\",\"decision\":\"{}\",\"samples_ns\":[{}]}}",
            escape(label),
            decision,
            values
        );
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
