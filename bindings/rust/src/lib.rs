//! Safe Rust wrapper for the YOG policy engine.
//!
//! The wrapper owns a compiled [`Yog`] and calls the public C ABI in
//! `yog/include/api/yog.h`. Like the C API, a compiled policy is immutable and
//! every check builds its own evaluator, so a `Yog` can be shared between
//! threads once its limits are set.
//!
//! ```no_run
//! use yog::{Decision, Yog};
//!
//! let policy = Yog::compile(
//!     "fact role(alice, admin)\n\
//!      allow can_access(User, Resource):\n\
//!          role(User, admin)\n",
//! )
//! .unwrap();
//! assert_eq!(
//!     policy.check("alice", "can_access", "db").unwrap(),
//!     Decision::Allow
//! );
//! ```

use std::ffi::{c_char, c_int, c_longlong, c_void, CStr, CString};
use std::fmt;
use std::ptr;

const MESSAGE_SIZE: usize = 192;

#[repr(C)]
struct RawError {
    line: c_int,
    column: c_int,
    message: [c_char; MESSAGE_SIZE],
}

// These three structs must match YogObligationArg, YogObligation and YogResult in
// yog/include/api/yog.h field for field: the C library writes through them.
#[repr(C)]
struct RawObligationArg {
    kind: c_int, // 0 text, 1 integer, 2 boolean
    text: *mut c_char,
    integer: c_longlong,
}

#[repr(C)]
struct RawObligation {
    name: *mut c_char,
    args: *mut RawObligationArg,
    arg_count: usize,
}

#[repr(C)]
struct RawResult {
    decision: c_int,
    reason: *mut c_char,
    trace: *mut c_char,
    matched_line: c_int,
    obligations: *mut RawObligation,
    obligation_count: usize,
}

impl RawResult {
    fn zeroed() -> Self {
        RawResult {
            decision: 1, // DENY: fail closed even if the call never fills it in
            reason: ptr::null_mut(),
            trace: ptr::null_mut(),
            matched_line: 0,
            obligations: ptr::null_mut(),
            obligation_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    /// Zero keeps the built-in default (1,000,000).
    pub max_steps: usize,
    /// Non-positive keeps the built-in default (256).
    pub max_depth: c_int,
    /// Solutions enumerated per query; zero keeps the default (100,000).
    pub max_solutions: usize,
    /// Wall-clock backstop per check in milliseconds; zero keeps the default (10,000).
    pub max_millis: usize,
    /// Evaluator memory per check in bytes; zero keeps the default (64 MiB).
    pub max_memory: usize,
}

extern "C" {
    fn yog_compile(source: *const c_char, length: usize, error: *mut RawError) -> *mut c_void;
    fn yog_free(yog: *mut c_void);
    fn yog_set_limits(yog: *mut c_void, limits: Limits);
    fn yog_get_limits(yog: *const c_void) -> Limits;
    fn yog_check(
        yog: *mut c_void,
        actor: *const c_char,
        action: *const c_char,
        resource: *const c_char,
        context: *const c_char,
        trace: bool,
        result: *mut RawResult,
        error: *mut RawError,
    ) -> bool;
    fn yog_result_free(result: *mut RawResult);
    fn yog_check_json(
        yog: *mut c_void,
        json: *const c_char,
        length: usize,
        trace: bool,
        result: *mut RawResult,
        error: *mut RawError,
    ) -> bool;
    fn yog_policy_version(yog: *const c_void) -> c_int;
    fn yog_version() -> *const c_char;
}

/// Version of this crate, kept equal to the C library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version string reported by the linked C library (for example "0.2.0-alpha.1").
pub fn library_version() -> String {
    // SAFETY: yog_version returns a pointer to a static NUL-terminated string.
    unsafe {
        let raw = yog_version();
        if raw.is_null() {
            String::new()
        } else {
            CStr::from_ptr(raw).to_string_lossy().into_owned()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    Allow,
    Deny,
    /// A human or other authority must approve this exact request before it runs.
    RequireApproval,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
            Decision::RequireApproval => "REQUIRE_APPROVAL",
        })
    }
}

/// An argument of an obligation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObligationArg {
    Text(String),
    Integer(i64),
    Boolean(bool),
}

/// Data a policy attaches to an ALLOW or REQUIRE_APPROVAL decision.  YOG never performs an
/// obligation: the enforcement point must, and must refuse the action if it cannot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obligation {
    pub name: String,
    pub args: Vec<ObligationArg>,
}

/// The full outcome of one check.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub decision: Decision,
    pub reason: String,
    pub matched_line: i32,
    pub obligations: Vec<Obligation>,
    pub trace: Option<String>,
}

fn text_of(raw: *const c_char) -> String {
    if raw.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned()
    }
}

/// Converts a filled-in C result, then always releases the C memory.
fn finish(ok: bool, result: &mut RawResult, error: &RawError) -> Result<Outcome, EvalError> {
    let outcome = if !ok {
        Err(EvalError {
            message: raw_message(error),
        })
    } else {
        match result.decision {
            0 | 1 | 2 => {
                let decision = match result.decision {
                    0 => Decision::Allow,
                    1 => Decision::Deny,
                    _ => Decision::RequireApproval,
                };
                let mut obligations = Vec::with_capacity(result.obligation_count);
                for i in 0..result.obligation_count {
                    let item = unsafe { &*result.obligations.add(i) };
                    let mut args = Vec::with_capacity(item.arg_count);
                    for k in 0..item.arg_count {
                        let arg = unsafe { &*item.args.add(k) };
                        args.push(match arg.kind {
                            1 => ObligationArg::Integer(arg.integer as i64),
                            2 => ObligationArg::Boolean(arg.integer != 0),
                            _ => ObligationArg::Text(text_of(arg.text)),
                        });
                    }
                    obligations.push(Obligation {
                        name: text_of(item.name),
                        args,
                    });
                }
                Ok(Outcome {
                    decision,
                    reason: text_of(result.reason),
                    matched_line: result.matched_line,
                    obligations,
                    trace: if result.trace.is_null() {
                        None
                    } else {
                        Some(text_of(result.trace))
                    },
                })
            }
            other => Err(EvalError {
                message: format!("the library returned an unknown decision value {other}"),
            }),
        }
    };
    unsafe { yog_result_free(result) };
    outcome
}

#[derive(Debug)]
pub struct CompileError {
    pub line: i32,
    pub column: i32,
    pub message: String,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for CompileError {}

#[derive(Debug)]
pub struct EvalError {
    pub message: String,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EvalError {}

/// A compiled, immutable policy.
pub struct Yog {
    handle: *mut c_void,
}

// The C API documents that a Yog is immutable after compilation and each check
// creates a fresh evaluator, so sharing is safe once limits are configured.
unsafe impl Send for Yog {}
unsafe impl Sync for Yog {}

impl Yog {
    pub fn compile(source: &str) -> Result<Self, CompileError> {
        let mut error = RawError {
            line: 0,
            column: 0,
            message: [0; MESSAGE_SIZE],
        };
        let handle = unsafe {
            yog_compile(
                source.as_ptr() as *const c_char,
                source.len(),
                &mut error,
            )
        };
        if handle.is_null() {
            return Err(CompileError {
                line: error.line,
                column: error.column,
                message: raw_message(&error),
            });
        }
        Ok(Self { handle })
    }

    pub fn limits(&self) -> Limits {
        unsafe { yog_get_limits(self.handle) }
    }

    pub fn set_limits(&mut self, limits: Limits) {
        unsafe { yog_set_limits(self.handle, limits) }
    }

    /// Return the decision for one request.
    ///
    /// An evaluation error is returned as `Err`; callers that need
    /// fail-closed behaviour must deny on `Err`.
    pub fn check(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
    ) -> Result<Decision, EvalError> {
        self.check_with_context(actor, action, resource, None, false)
            .map(|(decision, _)| decision)
    }

    /// Return `(decision, reason)` with an optional request context.
    ///
    /// The context is parsed as policy text, so it must only contain values you trust.  Use
    /// [`Yog::check_json`] for data that comes from an agent or a user.
    pub fn check_with_context(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        context: Option<&str>,
        trace: bool,
    ) -> Result<(Decision, String), EvalError> {
        self.decide(actor, action, resource, context, trace)
            .map(|outcome| (outcome.decision, outcome.reason))
    }

    /// Return the full [`Outcome`], including obligations.
    pub fn decide(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        context: Option<&str>,
        trace: bool,
    ) -> Result<Outcome, EvalError> {
        let actor = cstring(actor)?;
        let action = cstring(action)?;
        let resource = cstring(resource)?;
        let context = match context {
            Some(text) => cstring(text)?,
            None => CString::new("").expect("empty"),
        };
        let mut result = RawResult::zeroed();
        let mut error = RawError {
            line: 0,
            column: 0,
            message: [0; MESSAGE_SIZE],
        };
        let ok = unsafe {
            yog_check(
                self.handle,
                actor.as_ptr(),
                action.as_ptr(),
                resource.as_ptr(),
                context.as_ptr(),
                trace,
                &mut result,
                &mut error,
            )
        };
        finish(ok, &mut result, &error)
    }

    /// Check one request given as JSON (see docs/INTERFACES.md).  Request values never pass through
    /// policy text, so this is the safe entry point for untrusted data.  An `Err` must be treated
    /// as a DENY.
    pub fn check_json(&self, json: &str, trace: bool) -> Result<Outcome, EvalError> {
        let mut result = RawResult::zeroed();
        let mut error = RawError {
            line: 0,
            column: 0,
            message: [0; MESSAGE_SIZE],
        };
        let ok = unsafe {
            yog_check_json(
                self.handle,
                json.as_ptr() as *const c_char,
                json.len(),
                trace,
                &mut result,
                &mut error,
            )
        };
        finish(ok, &mut result, &error)
    }

    /// The language version the policy declared with `version N` (1 when absent).
    pub fn policy_version(&self) -> i32 {
        unsafe { yog_policy_version(self.handle) }
    }
}

impl Drop for Yog {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { yog_free(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

impl fmt::Debug for Yog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Yog")
            .field("limits", &self.limits())
            .finish_non_exhaustive()
    }
}

fn cstring(value: &str) -> Result<CString, EvalError> {
    CString::new(value).map_err(|_| EvalError {
        message: "request value contains an interior NUL byte".to_string(),
    })
}

fn raw_message(error: &RawError) -> String {
    let bytes: Vec<u8> = error
        .message
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

// ------------------------------------------------------------------------------------------------
// Guarding a tool call
// ------------------------------------------------------------------------------------------------

/// A flat tool-argument value.  Nested values are deliberately not supported: the request is built here, with every
/// string escaped, so that nothing an agent supplies can add or change a field of the request (the actor, the
/// environment, the facts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgValue {
    Text(String),
    Integer(i64),
    Boolean(bool),
}

/// The result of asking the policy about a tool call.
#[derive(Debug)]
pub enum Verdict<T> {
    /// The policy allowed the call and the tool ran.  `obligations` lists what the policy attached; every one of them
    /// is a name the caller declared it performs.
    Allowed {
        value: T,
        obligations: Vec<Obligation>,
    },
    /// Refused, or something needed to decide failed (a refusal either way).  The tool did not run.
    Denied { reason: String },
    /// A human must approve this exact call first.  The tool did not run.
    NeedsApproval { reason: String },
}

impl<T> Verdict<T> {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allowed { .. })
    }
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Puts a policy in front of one tool: `call` asks the policy and runs the tool only on ALLOW.
///
/// It fails closed: a policy error, an unknown decision, or an obligation the caller did not declare in `performs`
/// all refuse the call.  Like every in-process guard it can be bypassed by code that calls the tool directly; for
/// enforcement the agent must not hold the tool's credentials (docs/OPERATIONS.md).
pub struct GuardedTool<'a> {
    policy: &'a Yog,
    actor: String,
    tool: String,
    performs: Vec<String>,
}

impl<'a> GuardedTool<'a> {
    /// `performs` names the obligations (for example `"audit"`) the caller will carry out when a call is allowed.
    pub fn new(policy: &'a Yog, actor: &str, tool: &str, performs: &[&str]) -> Self {
        GuardedTool {
            policy,
            actor: actor.to_string(),
            tool: tool.to_string(),
            performs: performs.iter().map(|name| name.to_string()).collect(),
        }
    }

    /// The JSON request sent to the policy (see docs/INTERFACES.md); arguments appear as `input.<name>`.
    pub fn request_json(&self, args: &[(&str, ArgValue)]) -> String {
        let mut fields = Vec::with_capacity(args.len());
        for (name, value) in args {
            let rendered = match value {
                ArgValue::Text(text) => json_string(text),
                ArgValue::Integer(number) => number.to_string(),
                ArgValue::Boolean(flag) => flag.to_string(),
            };
            fields.push(format!("{}:{}", json_string(name), rendered));
        }
        format!(
            "{{\"actor\":{},\"action\":\"run_tool\",\"resource\":{},\"args\":{{\"input\":{{{}}}}}}}",
            json_string(&self.actor),
            json_string(&self.tool),
            fields.join(",")
        )
    }

    pub fn call<T>(&self, args: &[(&str, ArgValue)], run: impl FnOnce() -> T) -> Verdict<T> {
        let request = self.request_json(args);
        let outcome = match self.policy.check_json(&request, false) {
            Ok(outcome) => outcome,
            Err(error) => {
                return Verdict::Denied {
                    reason: format!("policy error: {}", error.message),
                }
            }
        };
        match outcome.decision {
            Decision::Allow => {
                for obligation in &outcome.obligations {
                    if !self.performs.iter().any(|name| *name == obligation.name) {
                        return Verdict::Denied {
                            reason: format!("cannot perform obligation {:?}", obligation.name),
                        };
                    }
                }
                Verdict::Allowed {
                    value: run(),
                    obligations: outcome.obligations,
                }
            }
            Decision::Deny => Verdict::Denied {
                reason: outcome.reason,
            },
            Decision::RequireApproval => Verdict::NeedsApproval {
                reason: outcome.reason,
            },
            #[allow(unreachable_patterns)]
            _ => Verdict::Denied {
                reason: "unknown decision".to_string(),
            },
        }
    }
}
