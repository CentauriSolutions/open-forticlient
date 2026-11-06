//! The failure type the verbs and the socket ops share.
//!
//! A verb prints [`Failure::text`] and exits with [`Failure::exit`]; the socket sends
//! the same failure as an error reply with [`Failure::code`]. Both come from one
//! value built where the failure happens, so the two cannot drift and nobody has to
//! recover a code by matching the text.

use oftc_ui_edge::{ErrorBody, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: ErrorCode,
    /// What the verb prints; the reply's `detail`, which the UI never shows verbatim.
    pub text: String,
    /// The verb's exit code (1 unless the verb says otherwise).
    pub exit: i32,
    pub profile_id: Option<String>,
}

impl Failure {
    pub fn new(code: ErrorCode, text: &str) -> Failure {
        Failure {
            code,
            text: text.to_owned(),
            exit: 1,
            profile_id: None,
        }
    }

    pub fn internal(text: &str) -> Failure {
        Failure::new(ErrorCode::Internal, text)
    }

    pub fn with_exit(mut self, exit: i32) -> Failure {
        self.exit = exit;
        self
    }

    pub fn for_profile(mut self, id: &str) -> Failure {
        self.profile_id = Some(id.to_owned());
        self
    }

    /// The error reply's body.
    pub fn body(&self) -> ErrorBody {
        let body = ErrorBody::new(self.code, &self.text);
        match &self.profile_id {
            Some(id) => body.for_profile(id),
            None => body,
        }
    }

    /// What a verb prints and returns for this failure.
    pub fn outcome(self) -> (String, i32) {
        (self.text, self.exit)
    }
}
