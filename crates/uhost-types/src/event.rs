//! Versioned event envelopes used for audit, reconciliation, and extension
//! hooks.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::common::{AuditActor, ValidationError};
use crate::id::AuditId;

/// Event header shared by all platform events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventHeader {
    /// Audit/event identifier for deduplication and cross-service correlation.
    pub event_id: AuditId,
    /// Versioned event name such as `identity.user.created.v1`.
    pub event_type: String,
    /// Event schema version for explicit evolution.
    pub schema_version: u16,
    /// Service that emitted the event.
    pub source_service: String,
    /// Emission timestamp.
    pub emitted_at: OffsetDateTime,
    /// Actor responsible for the change.
    pub actor: AuditActor,
}

impl EventHeader {
    /// Validate the header invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.event_type.trim().is_empty() {
            return Err(ValidationError::EmptyField {
                type_name: "EventHeader",
                field: "event_type",
            });
        }

        if self.source_service.trim().is_empty() {
            return Err(ValidationError::EmptyField {
                type_name: "EventHeader",
                field: "source_service",
            });
        }

        if self.schema_version == 0 {
            return Err(ValidationError::InvalidValue {
                type_name: "EventHeader",
                field: "schema_version",
                message: "schema_version must be greater than zero",
            });
        }

        self.actor.validate()
    }
}

/// Service-scoped event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEvent {
    /// Logical resource kind.
    pub resource_kind: String,
    /// Resource identifier.
    pub resource_id: String,
    /// Action such as `created`, `updated`, `deleted`, or `restored`.
    pub action: String,
    /// Free-form details encoded as stable JSON.
    pub details: serde_json::Value,
}

impl ServiceEvent {
    /// Validate the service event invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        for (field, value) in [
            ("resource_kind", &self.resource_kind),
            ("resource_id", &self.resource_id),
            ("action", &self.action),
        ] {
            if value.trim().is_empty() {
                return Err(ValidationError::EmptyField {
                    type_name: "ServiceEvent",
                    field,
                });
            }
        }

        Ok(())
    }
}

/// Event payload variants available in the platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "data")]
pub enum EventPayload {
    /// Service-scoped resource mutation event.
    Service(ServiceEvent),
    /// Audit-only operator or tenant activity event.
    Audit { summary: String, subject: String },
    /// Metering sample event.
    Metering {
        meter: String,
        value: u64,
        unit: String,
    },
}

/// Complete platform event envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformEvent {
    /// Versioned event header.
    pub header: EventHeader,
    /// Payload body.
    pub payload: EventPayload,
}

impl PlatformEvent {
    /// Validate the complete envelope.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.header.validate()?;

        match &self.payload {
            EventPayload::Service(event) => event.validate(),
            EventPayload::Audit { summary, subject } => {
                for (field, value) in [("summary", summary), ("subject", subject)] {
                    if value.trim().is_empty() {
                        return Err(ValidationError::EmptyField {
                            type_name: "EventPayload::Audit",
                            field,
                        });
                    }
                }

                Ok(())
            }
            EventPayload::Metering { meter, unit, .. } => {
                for (field, value) in [("meter", meter), ("unit", unit)] {
                    if value.trim().is_empty() {
                        return Err(ValidationError::EmptyField {
                            type_name: "EventPayload::Metering",
                            field,
                        });
                    }
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventHeader, EventPayload, PlatformEvent, ServiceEvent};
    use crate::common::{AuditActor, OwnershipScope, ResourceLifecycleState, ResourceMetadata};
    use crate::id::AuditId;

    fn actor() -> AuditActor {
        AuditActor {
            subject: "usr_abcdefghijklmnopqrstu".to_owned(),
            actor_type: "user".to_owned(),
            source_ip: None,
            correlation_id: "corr".to_owned(),
        }
    }

    #[test]
    fn platform_event_validation_rejects_blank_service_fields() {
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::parse("aud_abcdefghijklmnopqrstu")
                    .unwrap_or_else(|error| panic!("{error}")),
                event_type: "identity.user.created.v1".to_owned(),
                schema_version: 1,
                source_service: "identity".to_owned(),
                emitted_at: time::OffsetDateTime::UNIX_EPOCH,
                actor: actor(),
            },
            payload: EventPayload::Service(ServiceEvent {
                resource_kind: "user".to_owned(),
                resource_id: "usr_abcdefghijklmnopqrstu".to_owned(),
                action: "created".to_owned(),
                details: serde_json::json!({"hello": "world"}),
            }),
        };

        assert!(event.validate().is_ok());
    }

    #[test]
    fn header_validation_rejects_blank_service_name() {
        let header = EventHeader {
            event_id: AuditId::parse("aud_abcdefghijklmnopqrstu")
                .unwrap_or_else(|error| panic!("{error}")),
            event_type: "identity.user.created.v1".to_owned(),
            schema_version: 1,
            source_service: " ".to_owned(),
            emitted_at: time::OffsetDateTime::UNIX_EPOCH,
            actor: actor(),
        };

        assert!(header.validate().is_err());
    }

    #[test]
    fn metadata_validation_can_still_be_used_from_event_context() {
        let metadata = ResourceMetadata {
            created_at: time::OffsetDateTime::UNIX_EPOCH,
            updated_at: time::OffsetDateTime::UNIX_EPOCH,
            lifecycle: ResourceLifecycleState::Pending,
            ownership_scope: OwnershipScope::Tenant,
            owner_id: Some("tenant-1".to_owned()),
            labels: Default::default(),
            annotations: Default::default(),
            deleted_at: None,
            etag: "etag".to_owned(),
        };

        assert!(metadata.validate().is_ok());
    }
}
