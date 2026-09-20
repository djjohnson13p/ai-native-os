//! Deterministic, bounded diagnostic collection.

use aios_contracts::{Diagnostic, Severity, ValidatorReasonCode};

pub(crate) struct DiagnosticCollector {
    diagnostics: Vec<Diagnostic>,
    max: usize,
    truncated: bool,
    saw_error: bool,
}

impl DiagnosticCollector {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            diagnostics: Vec::new(),
            max,
            truncated: false,
            saw_error: false,
        }
    }

    pub(crate) fn push(&mut self, mut diagnostic: Diagnostic) {
        truncate_chars(&mut diagnostic.message, 4_096);
        truncate_optional(&mut diagnostic.node_id, 128);
        truncate_optional(&mut diagnostic.port, 128);
        truncate_optional(&mut diagnostic.capability, 160);
        truncate_optional(&mut diagnostic.json_pointer, 1_024);
        diagnostic.related.truncate(16);
        for related in &mut diagnostic.related {
            truncate_chars(related, 1_024);
        }
        self.saw_error |= diagnostic.severity == Severity::Error;
        if self.diagnostics.len() < self.max {
            self.diagnostics.push(diagnostic);
        } else {
            self.truncated = true;
        }
    }

    pub(crate) fn error(&mut self, code: ValidatorReasonCode, message: impl Into<String>) {
        self.push(Diagnostic::new(code, message));
    }

    pub(crate) fn has_errors(&self) -> bool {
        self.saw_error
    }

    pub(crate) fn is_truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn finish(mut self) -> (Vec<Diagnostic>, bool) {
        if self.truncated && self.max > 1 {
            let notice = Diagnostic::new(
                ValidatorReasonCode::IrLimitDiagnostics,
                "additional diagnostics were suppressed by the configured limit",
            );
            if self.diagnostics.len() == self.max {
                // Preserve the first/root error and replace the least-prioritized tail.
                self.diagnostics.pop();
            }
            self.diagnostics.push(notice);
        }
        (self.diagnostics, self.truncated)
    }
}

fn truncate_optional(value: &mut Option<String>, maximum: usize) {
    if let Some(value) = value {
        truncate_chars(value, maximum);
    }
}

fn truncate_chars(value: &mut String, maximum: usize) {
    if let Some((byte_index, _)) = value.char_indices().nth(maximum) {
        value.truncate(byte_index);
    }
}

pub(crate) fn contextual(
    code: ValidatorReasonCode,
    message: impl Into<String>,
    node_id: Option<&str>,
    port: Option<&str>,
    capability: Option<&str>,
    json_pointer: Option<String>,
) -> Diagnostic {
    let mut diagnostic = Diagnostic::new(code, message);
    diagnostic.node_id = node_id.map(str::to_owned);
    diagnostic.port = port.map(str::to_owned);
    diagnostic.capability = capability.map(str::to_owned);
    diagnostic.json_pointer = json_pointer;
    diagnostic
}
