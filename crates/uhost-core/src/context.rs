//! Request context propagation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uhost_types::PrincipalIdentity;

use crate::crypto::random_bytes;
use crate::error::{PlatformError, Result};

/// Request-scoped context propagated across service boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    /// Correlation identifier shared across a multi-service request.
    pub correlation_id: String,
    /// Per-hop request identifier.
    pub request_id: String,
    /// Request start timestamp.
    pub started_at: OffsetDateTime,
    /// Optional authenticated subject.
    pub actor: Option<String>,
    /// Optional typed principal envelope resolved for this request.
    pub principal: Option<PrincipalIdentity>,
    /// Optional tenant scope.
    pub tenant_id: Option<String>,
    /// Feature flags in effect for this request.
    pub feature_flags: BTreeSet<String>,
}

impl RequestContext {
    /// Create a new root context.
    pub fn new() -> Result<Self> {
        Ok(Self {
            correlation_id: Self::generate_token()?,
            request_id: Self::generate_token()?,
            started_at: OffsetDateTime::now_utc(),
            actor: None,
            principal: None,
            tenant_id: None,
            feature_flags: BTreeSet::new(),
        })
    }

    /// Create a child context that keeps correlation but gets a new request ID.
    pub fn child(&self) -> Result<Self> {
        let mut child = self.clone();
        child.request_id = Self::generate_token()?;
        child.started_at = OffsetDateTime::now_utc();
        Ok(child)
    }

    fn generate_token() -> Result<String> {
        let bytes = random_bytes(18)?;
        let mut value = String::from("ctx_");
        value.push_str(&crate::crypto::base64url_encode(&bytes));
        Ok(value)
    }

    /// Attach a tenant scope.
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Attach an actor subject.
    pub fn with_actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    /// Attach a typed principal envelope.
    pub fn with_principal(mut self, principal: PrincipalIdentity) -> Self {
        self.set_principal(principal);
        self
    }

    /// Mutably attach a typed principal envelope.
    pub fn set_principal(&mut self, principal: PrincipalIdentity) {
        if self.actor.is_none() {
            self.actor = Some(principal.subject.clone());
        }
        self.principal = Some(principal);
    }
}

impl From<PlatformError> for RequestContext {
    fn from(_: PlatformError) -> Self {
        Self {
            correlation_id: String::from("ctx_error"),
            request_id: String::from("ctx_error"),
            started_at: OffsetDateTime::now_utc(),
            actor: None,
            principal: None,
            tenant_id: None,
            feature_flags: BTreeSet::new(),
        }
    }
}
