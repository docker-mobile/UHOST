//! Minimal structured logger.

use std::collections::BTreeMap;
use std::io::{self, Write};

use serde::Serialize;
use time::OffsetDateTime;

use crate::context::RequestContext;

/// Structured log level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Verbose debugging information.
    Debug,
    /// Informational operational event.
    Info,
    /// Warning that did not fail the request outright.
    Warn,
    /// Request or subsystem failure.
    Error,
}

/// Field attached to a structured log record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogField {
    /// Field name.
    pub key: String,
    /// Field value.
    pub value: String,
}

impl LogField {
    /// Build a new log field.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Very small JSON logger that writes one record per line.
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonLogger;

impl JsonLogger {
    /// Emit a structured log entry.
    pub fn log(
        &self,
        level: LogLevel,
        service: &str,
        message: &str,
        context: Option<&RequestContext>,
        fields: &[LogField],
    ) {
        let mut extra = BTreeMap::new();
        for field in fields {
            extra.insert(field.key.clone(), field.value.clone());
        }

        if let Some(context) = context {
            extra.insert(
                String::from("correlation_id"),
                context.correlation_id.clone(),
            );
            extra.insert(String::from("request_id"), context.request_id.clone());
            if let Some(actor) = &context.actor {
                extra.insert(String::from("actor"), actor.clone());
            }
        }

        let record = serde_json::json!({
            "ts": OffsetDateTime::now_utc(),
            "level": level,
            "service": service,
            "message": message,
            "fields": extra,
        });

        let mut stderr = io::stderr().lock();
        let _ = writeln!(stderr, "{record}");
    }
}
