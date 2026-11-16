//! In-process benchmark driver for the Rust binding.
//!
//! Reads a tab-separated request file (`label<TAB>actor<TAB>action<TAB>resource<TAB>context`)
//! and prints one JSON object per request with the decision and per-call
//! nanosecond samples.  Keeping the loop inside the process is the whole point:
//! it measures the engine, not process startup.
//!
//! Usage:
//!   yog_bench --policy P --requests R [--iterations N] [--warmup N]
//!             [--mode load|warm]

use std::env;
use std::fs;
use std::process;
use std::time::Instant;

use yog::Yog;

struct Args {
    policy: String,
    requests: String,
    iterations: usize,
    warmup: usize,
    mode: String,
}

fn parse_args() -> Args {
    let mut args = Args {
        policy: String::new(),
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
    if args.policy.is_empty() {
        eprintln!("--policy is required");
        process::exit(2);
    }
    args
}

fn main() {
    let args = parse_args();
    let source = fs::read_to_string(&args.policy).unwrap_or_else(|error| {
        eprintln!("cannot read policy: {error}");
        process::exit(1);
    });

    let compile_started = Instant::now();
    let policy = Yog::compile(&source).unwrap_or_else(|error| {
        eprintln!("compile error: {error}");
        process::exit(1);
    });
    let compile_ns = compile_started.elapsed().as_nanos();

    if args.mode == "load" {
        println!(
            "{{\"mode\":\"load\",\"compile_ns\":{},\"limits\":{{\"max_steps\":{},\"max_depth\":{}}}}}",
            compile_ns,
            policy.limits().max_steps,
            policy.limits().max_depth
        );
        return;
    }

    let text = fs::read_to_string(&args.requests).unwrap_or_else(|error| {
        eprintln!("cannot read requests: {error}");
        process::exit(1);
    });

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
        let context = fields.get(4).copied().unwrap_or("");

        let mut decision = None;
        for _ in 0..args.warmup {
            decision = Some(
                policy
                    .check_with_context(actor, action, resource, Some(context), false)
                    .unwrap_or_else(|error| {
                        eprintln!("evaluation error: {error}");
                        process::exit(1);
                    })
                    .0,
            );
        }
        if decision.is_none() {
            decision = Some(
                policy
                    .check_with_context(actor, action, resource, Some(context), false)
                    .unwrap_or_else(|error| {
                        eprintln!("evaluation error: {error}");
                        process::exit(1);
                    })
                    .0,
            );
        }

        let mut samples = Vec::with_capacity(args.iterations);
        for _ in 0..args.iterations {
            let started = Instant::now();
            let outcome = policy
                .check_with_context(actor, action, resource, Some(context), false)
                .unwrap_or_else(|error| {
                    eprintln!("evaluation error: {error}");
                    process::exit(1);
                })
                .0;
            samples.push(started.elapsed().as_nanos());
            decision = Some(outcome);
        }

        let values = samples
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{{\"label\":\"{}\",\"decision\":\"{}\",\"samples_ns\":[{}]}}",
            escape(label),
            decision.expect("decision"),
            values
        );
    }
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
