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

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::fmt;
use std::ptr;

const MESSAGE_SIZE: usize = 192;

#[repr(C)]
struct RawError {
    line: c_int,
    column: c_int,
    message: [c_char; MESSAGE_SIZE],
}

#[repr(C)]
struct RawResult {
    decision: c_int,
    reason: *mut c_char,
    trace: *mut c_char,
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Decision::Allow => "ALLOW",
            Decision::Deny => "DENY",
        })
    }
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
    pub fn check_with_context(
        &self,
        actor: &str,
        action: &str,
        resource: &str,
        context: Option<&str>,
        trace: bool,
    ) -> Result<(Decision, String), EvalError> {
        let actor = cstring(actor)?;
        let action = cstring(action)?;
        let resource = cstring(resource)?;
        let context = match context {
            Some(text) => cstring(text)?,
            None => CString::new("").expect("empty"),
        };

        let mut result = RawResult {
            decision: 0,
            reason: ptr::null_mut(),
            trace: ptr::null_mut(),
        };
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
        let outcome = if !ok {
            Err(EvalError {
                message: raw_message(&error),
            })
        } else {
            let decision = if result.decision == 0 {
                Decision::Allow
            } else {
                Decision::Deny
            };
            let reason = if result.reason.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(result.reason) }
                    .to_string_lossy()
                    .into_owned()
            };
            Ok((decision, reason))
        };
        unsafe { yog_result_free(&mut result) };
        outcome
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
