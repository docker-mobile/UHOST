//! Secrets management service.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{
    PlatformError, RequestContext, Result, SecretBytes, SecretString, seal_secret, sha256_hex,
    unseal_secret,
};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox, OutboxMessage, StoredDocument};
use uhost_types::{
    ApprovalId, AuditActor, AuditId, EventHeader, EventPayload, OwnershipScope, PlatformEvent,
    PrincipalKind, ResourceMetadata, SecretId, ServiceEvent,
};

const SECRETS_EVENTS_TOPIC: &str = "secrets.events.v1";

/// Stored secret metadata and ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecord {
    pub id: SecretId,
    pub name: String,
    pub version: u32,
    pub ciphertext: String,
    pub metadata: ResourceMetadata,
}

/// Persisted read-only summary of secret records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretsSummary {
    /// Total number of active secret records.
    pub secret_count: usize,
    /// Total number of unique logical secret names.
    pub unique_secret_name_count: usize,
    /// Highest active secret version.
    pub highest_version: u32,
    /// Latest active version per secret name.
    pub latest_version_by_name: BTreeMap<String, u32>,
    /// Active secret record totals by ownership scope.
    pub ownership_scope_totals: BTreeMap<String, usize>,
}

/// Durable authorization kind used for a non-direct secret reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRevealGrantKind {
    /// One explicit approval authorizes a single reveal.
    Approval,
    /// A time-bounded lease authorizes repeated reveals until expiry.
    Lease,
}

impl SecretRevealGrantKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Lease => "lease",
        }
    }

    fn created_event_type(self) -> &'static str {
        match self {
            Self::Approval => "secrets.reveal.approved.v1",
            Self::Lease => "secrets.reveal.leased.v1",
        }
    }

    fn created_action(self) -> &'static str {
        match self {
            Self::Approval => "approved",
            Self::Lease => "leased",
        }
    }
}

/// Durable approval or lease record that authorizes one non-direct secret reveal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRevealGrantRecord {
    /// Stable approval-style identifier for this reveal grant.
    pub id: ApprovalId,
    /// Secret authorized by this grant.
    pub secret_id: SecretId,
    /// Authorization kind.
    pub grant_kind: SecretRevealGrantKind,
    /// Operator-supplied reason for the grant.
    pub reason: String,
    /// Subject that granted the reveal authorization.
    pub granted_by: String,
    /// Principal kind used when the grant was created.
    pub granted_by_kind: String,
    /// Grant creation timestamp.
    pub granted_at: OffsetDateTime,
    /// Expiry timestamp for lease-backed grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<OffsetDateTime>,
    /// Number of successful reveals performed under this grant.
    #[serde(default)]
    pub reveal_count: u32,
    /// Timestamp of the latest reveal performed under this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_revealed_at: Option<OffsetDateTime>,
    /// Subject that most recently used this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_revealed_by: Option<String>,
    /// Principal kind that most recently used this grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_revealed_by_kind: Option<String>,
    /// Shared resource metadata.
    pub metadata: ResourceMetadata,
}

impl SecretRevealGrantRecord {
    fn new(
        id: ApprovalId,
        secret_id: SecretId,
        grant_kind: SecretRevealGrantKind,
        reason: String,
        granted_by: String,
        granted_by_kind: String,
        granted_at: OffsetDateTime,
        expires_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            id,
            secret_id,
            grant_kind,
            reason,
            granted_by,
            granted_by_kind,
            granted_at,
            expires_at,
            reveal_count: 0,
            last_revealed_at: None,
            last_revealed_by: None,
            last_revealed_by_kind: None,
        }
    }

    fn ensure_usable_at(&self, now: OffsetDateTime) -> Result<()> {
        if self.grant_kind == SecretRevealGrantKind::Approval && self.reveal_count > 0 {
            return Err(PlatformError::conflict(
                "secret reveal approval has already been used",
            ));
        }
        if self.expires_at.is_some_and(|expires_at| now > expires_at) {
            return Err(PlatformError::conflict("secret reveal lease has expired"));
        }
        Ok(())
    }

    fn record_reveal(
        &mut self,
        revealed_by: String,
        revealed_by_kind: String,
        revealed_at: OffsetDateTime,
    ) {
        self.reveal_count = self.reveal_count.saturating_add(1);
        self.last_revealed_at = Some(revealed_at);
        self.last_revealed_by = Some(revealed_by);
        self.last_revealed_by_kind = Some(revealed_by_kind);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSecretRequest {
    name: String,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSecretRevealApprovalRequest {
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSecretRevealLeaseRequest {
    reason: String,
    lease_seconds: u32,
}

fn normalize_secret_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("secret name must not be empty"));
    }
    if trimmed.len() > 128 {
        return Err(PlatformError::invalid("secret name exceeds 128 bytes"));
    }
    Ok(trimmed.to_owned())
}

/// Secrets service.
#[derive(Debug, Clone)]
pub struct SecretsService {
    secrets: DocumentStore<SecretRecord>,
    reveal_grants: DocumentStore<SecretRevealGrantRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    master_key: SecretBytes,
    state_root: PathBuf,
    version_guard: Arc<Mutex<()>>,
}

impl SecretsService {
    /// Open secret state with an explicit master key.
    pub async fn open(state_root: impl AsRef<Path>, master_key: SecretBytes) -> Result<Self> {
        let root = state_root.as_ref().join("secrets");
        Ok(Self {
            secrets: DocumentStore::open(root.join("secrets.json")).await?,
            reveal_grants: DocumentStore::open(root.join("reveal_grants.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            master_key,
            state_root: root,
            version_guard: Arc::new(Mutex::new(())),
        })
    }

    async fn list_secrets(&self) -> Result<Vec<SecretRecord>> {
        Ok(self
            .secrets
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect())
    }

    async fn create_secret(
        &self,
        request: CreateSecretRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        require_non_workload_principal_or_local_dev(context, "secrets control plane")?;
        let name = normalize_secret_name(&request.name)?;
        // Serialize version allocation to avoid duplicate versions for the same name.
        let _guard = self.version_guard.lock().await;
        let next_version = self
            .secrets
            .list()
            .await?
            .into_iter()
            .map(|(_, record)| record.value)
            .filter(|record| record.name == name)
            .map(|record| record.version)
            .max()
            .unwrap_or(0)
            + 1;
        let id = SecretId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate secret id")
                .with_detail(error.to_string())
        })?;
        let ciphertext = seal_secret(&self.master_key, &SecretString::new(request.value))?;
        let record = SecretRecord {
            id: id.clone(),
            name,
            version: next_version,
            ciphertext,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.secrets.create(id.as_str(), record.clone()).await?;
        json_response(
            StatusCode::CREATED,
            &serde_json::json!({
                "id": record.id,
                "name": record.name,
                "version": record.version,
            }),
        )
    }

    async fn summary(&self) -> Result<http::Response<ApiBody>> {
        let mut secret_count = 0_usize;
        let mut names = BTreeSet::new();
        let mut highest_version = 0_u32;
        let mut latest_version_by_name = BTreeMap::new();
        let mut ownership_scope_totals = BTreeMap::new();

        for (_, stored) in self.secrets.list().await? {
            if stored.deleted {
                continue;
            }
            let record = stored.value;
            secret_count += 1;
            names.insert(record.name.clone());
            highest_version = highest_version.max(record.version);

            let latest = latest_version_by_name.entry(record.name).or_insert(0);
            *latest = (*latest).max(record.version);

            let scope = ownership_scope_key(record.metadata.ownership_scope);
            let total = ownership_scope_totals.entry(scope).or_insert(0);
            *total += 1;
        }

        json_response(
            StatusCode::OK,
            &SecretsSummary {
                secret_count,
                unique_secret_name_count: names.len(),
                highest_version,
                latest_version_by_name,
                ownership_scope_totals,
            },
        )
    }

    async fn lookup_active_secret(&self, secret_id: &str) -> Result<StoredDocument<SecretRecord>> {
        let record = self
            .secrets
            .get(secret_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("secret does not exist"))?;
        if record.deleted {
            return Err(PlatformError::not_found("secret does not exist"));
        }
        Ok(record)
    }

    async fn reveal_secret_with_authorization(
        &self,
        secret_id: &str,
        authorization: Option<&SecretRevealGrantRecord>,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let record = self.lookup_active_secret(secret_id).await?;
        let plaintext = unseal_secret(&self.master_key, &record.value.ciphertext)?;
        let authorization_kind = authorization
            .map(|grant| grant.grant_kind.as_str())
            .unwrap_or("direct");
        self.append_event(
            "secrets.reveal.executed.v1",
            "secret",
            record.value.id.as_str(),
            "revealed",
            serde_json::json!({
                "secret_name": record.value.name,
                "secret_version": record.value.version,
                "authorization_kind": authorization_kind,
                "authorization_id": authorization.map(|grant| grant.id.to_string()),
                "lease_expires_at": authorization.and_then(|grant| grant.expires_at),
                "grant_reveal_count": authorization.map(|grant| grant.reveal_count),
            }),
            context,
        )
        .await?;
        json_response(
            StatusCode::OK,
            &serde_json::json!({
                "id": record.value.id,
                "name": record.value.name,
                "version": record.value.version,
                "value": plaintext.expose(),
            }),
        )
    }

    async fn reveal_secret(
        &self,
        secret_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        require_non_workload_principal_or_local_dev(context, "secret reveal")?;
        self.reveal_secret_with_authorization(secret_id, None, context)
            .await
    }

    async fn create_reveal_grant(
        &self,
        secret_id: &str,
        grant_kind: SecretRevealGrantKind,
        lease_seconds: Option<u32>,
        reason: &str,
        context: &RequestContext,
    ) -> Result<SecretRevealGrantRecord> {
        require_non_workload_principal_or_local_dev(context, "secret reveal approval")?;
        let secret = self.lookup_active_secret(secret_id).await?;
        let reason = normalize_reveal_reason(reason)?;
        let granted_at = OffsetDateTime::now_utc();
        let expires_at = match grant_kind {
            SecretRevealGrantKind::Approval => None,
            SecretRevealGrantKind::Lease => Some(
                granted_at
                    + Duration::seconds(i64::from(
                        lease_seconds
                            .filter(|seconds| *seconds > 0)
                            .ok_or_else(|| {
                                PlatformError::invalid(
                                    "secret reveal lease must be at least one second",
                                )
                            })?,
                    )),
            ),
        };
        let id = ApprovalId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate secret reveal approval id")
                .with_detail(error.to_string())
        })?;
        let (granted_by, granted_by_kind) = actor_subject_and_type(context);
        let grant = SecretRevealGrantRecord::new(
            id.clone(),
            secret.value.id.clone(),
            grant_kind,
            reason.clone(),
            granted_by,
            granted_by_kind,
            granted_at,
            expires_at,
        );
        self.reveal_grants
            .create(id.as_str(), grant.clone())
            .await?;
        self.append_event(
            grant_kind.created_event_type(),
            "secret_reveal_grant",
            id.as_str(),
            grant_kind.created_action(),
            serde_json::json!({
                "secret_id": secret.value.id,
                "secret_name": secret.value.name,
                "secret_version": secret.value.version,
                "grant_kind": grant_kind.as_str(),
                "reason": reason,
                "lease_seconds": lease_seconds,
                "expires_at": expires_at,
            }),
            context,
        )
        .await?;
        Ok(grant)
    }

    /// Create one durable approval-backed reveal grant for an existing secret.
    pub async fn approve_secret_reveal(
        &self,
        secret_id: &str,
        reason: &str,
        context: &RequestContext,
    ) -> Result<SecretRevealGrantRecord> {
        self.create_reveal_grant(
            secret_id,
            SecretRevealGrantKind::Approval,
            None,
            reason,
            context,
        )
        .await
    }

    async fn approve_secret_reveal_route(
        &self,
        secret_id: &str,
        request: CreateSecretRevealApprovalRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let grant = self
            .approve_secret_reveal(secret_id, &request.reason, context)
            .await?;
        json_response(StatusCode::CREATED, &grant)
    }

    /// Create one durable lease-backed reveal grant for an existing secret.
    pub async fn issue_secret_reveal_lease(
        &self,
        secret_id: &str,
        lease_seconds: u32,
        reason: &str,
        context: &RequestContext,
    ) -> Result<SecretRevealGrantRecord> {
        self.create_reveal_grant(
            secret_id,
            SecretRevealGrantKind::Lease,
            Some(lease_seconds),
            reason,
            context,
        )
        .await
    }

    async fn issue_secret_reveal_lease_route(
        &self,
        secret_id: &str,
        request: CreateSecretRevealLeaseRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let grant = self
            .issue_secret_reveal_lease(secret_id, request.lease_seconds, &request.reason, context)
            .await?;
        json_response(StatusCode::CREATED, &grant)
    }

    /// Reveal one secret using a previously approved or lease-backed reveal grant.
    pub async fn reveal_secret_with_grant(
        &self,
        secret_id: &str,
        grant_id: &str,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        require_non_workload_principal_or_local_dev(context, "secret reveal")?;
        let stored_grant = self
            .reveal_grants
            .get(grant_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("secret reveal approval does not exist"))?;
        if stored_grant.deleted {
            return Err(PlatformError::not_found(
                "secret reveal approval does not exist",
            ));
        }
        let mut grant = stored_grant.value;
        let secret = self.lookup_active_secret(secret_id).await?;
        if grant.secret_id != secret.value.id {
            return Err(PlatformError::conflict(
                "secret reveal approval does not match the requested secret",
            ));
        }
        let now = OffsetDateTime::now_utc();
        grant.ensure_usable_at(now)?;
        let (revealed_by, revealed_by_kind) = actor_subject_and_type(context);
        grant.record_reveal(revealed_by, revealed_by_kind, now);
        self.reveal_grants
            .upsert(grant.id.as_str(), grant.clone(), Some(stored_grant.version))
            .await?;
        self.reveal_secret_with_authorization(secret_id, Some(&grant), context)
            .await
    }

    async fn append_event(
        &self,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
        details: serde_json::Value,
        context: &RequestContext,
    ) -> Result<()> {
        let (actor_subject, actor_type) = actor_subject_and_type(context);
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("secrets"),
                emitted_at: OffsetDateTime::now_utc(),
                actor: AuditActor {
                    subject: actor_subject,
                    actor_type,
                    source_ip: None,
                    correlation_id: context.correlation_id.clone(),
                },
            },
            payload: EventPayload::Service(ServiceEvent {
                resource_kind: resource_kind.to_owned(),
                resource_id: resource_id.to_owned(),
                action: action.to_owned(),
                details,
            }),
        };
        self.audit_log.append(&event).await?;
        let idempotency = event.header.event_id.to_string();
        let _ = self
            .outbox
            .enqueue(SECRETS_EVENTS_TOPIC, event, Some(&idempotency))
            .await?;
        Ok(())
    }

    /// List all durable outbox messages emitted by the secrets service.
    pub async fn list_outbox_messages(&self) -> Result<Vec<OutboxMessage<PlatformEvent>>> {
        self.outbox.list_all().await
    }
}

impl HttpService for SecretsService {
    fn name(&self) -> &'static str {
        "secrets"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/secrets")];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        context: RequestContext,
    ) -> ResponseFuture<'a> {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["secrets"]) => {
                    require_non_workload_principal_or_local_dev(&context, "secrets control plane")?;
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "service": self.name(),
                            "state_root": self.state_root,
                        }),
                    )
                    .map(Some)
                }
                (Method::GET, ["secrets", "items"]) => {
                    require_non_workload_principal_or_local_dev(&context, "secrets control plane")?;
                    let values = self
                        .list_secrets()
                        .await?
                        .into_iter()
                        .map(|record| {
                            serde_json::json!({
                                "id": record.id,
                                "name": record.name,
                                "version": record.version,
                            })
                        })
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["secrets", "summary"]) => {
                    require_non_workload_principal_or_local_dev(&context, "secrets control plane")?;
                    self.summary().await.map(Some)
                }
                (Method::POST, ["secrets", "items"]) => {
                    let body: CreateSecretRequest = parse_json(request).await?;
                    self.create_secret(body, &context).await.map(Some)
                }
                (Method::POST, ["secrets", "items", secret_id, "reveal", "approvals"]) => {
                    let body: CreateSecretRevealApprovalRequest = parse_json(request).await?;
                    self.approve_secret_reveal_route(secret_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["secrets", "items", secret_id, "reveal", "leases"]) => {
                    let body: CreateSecretRevealLeaseRequest = parse_json(request).await?;
                    self.issue_secret_reveal_lease_route(secret_id, body, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["secrets", "items", secret_id, "reveal", "grants", grant_id]) => {
                    self.reveal_secret_with_grant(secret_id, grant_id, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["secrets", "items", secret_id, "reveal"]) => {
                    self.reveal_secret(secret_id, &context).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn ownership_scope_key(scope: OwnershipScope) -> String {
    String::from(match scope {
        OwnershipScope::Platform => "platform",
        OwnershipScope::Tenant => "tenant",
        OwnershipScope::Project => "project",
        OwnershipScope::User => "user",
    })
}

fn require_non_workload_principal_or_local_dev(
    context: &RequestContext,
    capability: &str,
) -> Result<()> {
    if let Some(principal) = context.principal.as_ref()
        && principal.kind == PrincipalKind::Workload
    {
        return Err(PlatformError::forbidden(format!(
            "{capability} requires an authenticated non-workload principal"
        ))
        .with_correlation_id(context.correlation_id.clone()));
    }
    Ok(())
}

fn normalize_reveal_reason(reason: &str) -> Result<String> {
    let trimmed = reason.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "secret reveal reason must not be empty",
        ));
    }
    if trimmed.len() > 256 {
        return Err(PlatformError::invalid(
            "secret reveal reason exceeds 256 bytes",
        ));
    }
    Ok(trimmed.to_owned())
}

fn actor_subject_and_type(context: &RequestContext) -> (String, String) {
    let subject = context
        .principal
        .as_ref()
        .map(|principal| principal.subject.clone())
        .or_else(|| context.actor.clone())
        .unwrap_or_else(|| String::from("system"));
    let actor_type = context
        .principal
        .as_ref()
        .map(|principal| principal.kind.as_str().to_owned())
        .unwrap_or_else(|| String::from("principal"));
    (subject, actor_type)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bytes::Bytes;
    use http::{Method, Request, StatusCode};
    use http_body_util::{BodyExt, Full};
    use serde::de::DeserializeOwned;
    use tempfile::{TempDir, tempdir};
    use uhost_api::ApiBody;
    use uhost_core::{ErrorCode, PrincipalIdentity, PrincipalKind, RequestContext, SecretBytes};
    use uhost_runtime::HttpService;
    use uhost_types::EventPayload;

    use super::{
        CreateSecretRequest, CreateSecretRevealApprovalRequest, CreateSecretRevealLeaseRequest,
        SecretRevealGrantKind, SecretRevealGrantRecord, SecretsService,
    };

    fn master_key() -> SecretBytes {
        SecretBytes::new(vec![0_u8; 32])
    }

    fn operator_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(
                PrincipalKind::Operator,
                "bootstrap_admin",
            ))
    }

    async fn create_secret_and_get_id(
        service: &SecretsService,
        name: &str,
        value: &str,
        context: &RequestContext,
    ) -> String {
        let created = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from(name),
                    value: String::from(value),
                },
                context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let response: serde_json::Value =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        response["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing secret id"))
            .to_owned()
    }

    fn read_service_file(temp: &TempDir, file_name: &str) -> String {
        fs::read_to_string(temp.path().join("secrets").join(file_name))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    fn service_request(
        method: Method,
        uri: &str,
        body: Option<&str>,
    ) -> Request<uhost_runtime::RequestBody> {
        let mut builder = Request::builder().method(method).uri(uri);
        if body.is_some() {
            builder = builder.header(http::header::CONTENT_TYPE, "application/json");
        }
        builder
            .body(uhost_runtime::RequestBody::Right(Full::new(Bytes::from(
                body.unwrap_or_default().to_owned(),
            ))))
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn dispatch_request(
        service: &SecretsService,
        method: Method,
        uri: &str,
        body: Option<&str>,
        context: RequestContext,
    ) -> http::Response<ApiBody> {
        match service
            .handle(service_request(method, uri, body), context)
            .await
        {
            Ok(Some(response)) => response,
            Ok(None) => panic!("route {uri} was not handled"),
            Err(error) => panic!("{error}"),
        }
    }

    async fn response_json<T: DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let payload = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn create_secret_normalizes_names_and_versions_by_canonical_name() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let first = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("  api-key  "),
                    value: String::from("first-value"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_response: serde_json::Value =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first_response["name"], "api-key");
        assert_eq!(first_response["version"], 1);

        let second = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("api-key"),
                    value: String::from("second-value"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_payload = http_body_util::BodyExt::collect(second.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let second_response: serde_json::Value =
            serde_json::from_slice(&second_payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second_response["name"], "api-key");
        assert_eq!(second_response["version"], 2);
    }

    #[tokio::test]
    async fn empty_secret_names_are_rejected() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let error = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("   "),
                    value: String::from("value"),
                },
                &context,
            )
            .await
            .expect_err("blank names should be rejected");
        assert_eq!(error.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn list_and_reveal_skip_soft_deleted_secrets() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let created = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("database-password"),
                    value: String::from("super-secret"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let created_response: serde_json::Value =
            serde_json::from_slice(&created_payload).unwrap_or_else(|error| panic!("{error}"));
        let secret_id = created_response["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing secret id"))
            .to_owned();

        service
            .secrets
            .soft_delete(&secret_id, Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let listed = service
            .list_secrets()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(listed.is_empty());

        let error = service
            .reveal_secret(&secret_id, &context)
            .await
            .expect_err("soft-deleted secrets should not be revealed");
        assert_eq!(error.code, ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn reveal_secret_returns_plaintext_for_active_record() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let created = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("app-token"),
                    value: String::from("plaintext-value"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let created_payload = http_body_util::BodyExt::collect(created.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let created_response: serde_json::Value =
            serde_json::from_slice(&created_payload).unwrap_or_else(|error| panic!("{error}"));
        let secret_id = created_response["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing secret id"))
            .to_owned();

        let response = service
            .reveal_secret(&secret_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let revealed: serde_json::Value =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(revealed["value"], "plaintext-value");
    }

    #[tokio::test]
    async fn direct_reveal_emits_audit_and_outbox_without_logging_plaintext() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();
        let secret_id =
            create_secret_and_get_id(&service, "audit-secret", "plaintext-value", &context).await;

        let _response = service
            .reveal_secret(&secret_id, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let messages = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 1);
        let message = &messages[0];
        assert_eq!(message.topic, "secrets.events.v1");
        assert_eq!(
            message.payload.header.event_type,
            "secrets.reveal.executed.v1"
        );
        assert_eq!(message.payload.header.source_service, "secrets");
        assert_eq!(message.payload.header.actor.subject, "bootstrap_admin");
        if let EventPayload::Service(event) = &message.payload.payload {
            let details = event
                .details
                .as_object()
                .unwrap_or_else(|| panic!("expected object details"));
            assert_eq!(event.resource_kind, "secret");
            assert_eq!(event.resource_id, secret_id);
            assert_eq!(event.action, "revealed");
            assert_eq!(
                details.get("secret_name"),
                Some(&serde_json::json!("audit-secret"))
            );
            assert_eq!(details.get("secret_version"), Some(&serde_json::json!(1)));
            assert_eq!(
                details.get("authorization_kind"),
                Some(&serde_json::json!("direct"))
            );
            assert!(matches!(
                details.get("authorization_id"),
                Some(value) if value.is_null()
            ));
            assert!(matches!(
                details.get("lease_expires_at"),
                Some(value) if value.is_null()
            ));
            assert!(matches!(
                details.get("grant_reveal_count"),
                Some(value) if value.is_null()
            ));
            assert!(!details.contains_key("value"));
        } else {
            panic!("expected service payload");
        }

        let audit_log = read_service_file(&temp, "audit.log");
        assert!(audit_log.contains("secrets.reveal.executed.v1"));
        assert!(!audit_log.contains("plaintext-value"));
        let outbox = read_service_file(&temp, "outbox.json");
        assert!(outbox.contains("secrets.reveal.executed.v1"));
        assert!(!outbox.contains("plaintext-value"));
    }

    #[tokio::test]
    async fn approval_grant_and_reveal_emit_audit_and_outbox_events() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();
        let secret_id =
            create_secret_and_get_id(&service, "grant-secret", "grant-value", &context).await;

        let grant = service
            .approve_secret_reveal(&secret_id, "breakglass validation", &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(grant.grant_kind, SecretRevealGrantKind::Approval);

        let response = service
            .reveal_secret_with_grant(&secret_id, grant.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = http_body_util::BodyExt::collect(response.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let revealed: serde_json::Value =
            serde_json::from_slice(&payload).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(revealed["value"], "grant-value");

        let stored_grant = service
            .reveal_grants
            .get(grant.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reveal grant"));
        assert_eq!(stored_grant.value.reveal_count, 1);
        assert_eq!(
            stored_grant.value.last_revealed_by.as_deref(),
            Some("bootstrap_admin")
        );

        let messages = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 2);
        let event_types = messages
            .iter()
            .map(|message| message.payload.header.event_type.clone())
            .collect::<Vec<_>>();
        assert!(event_types.contains(&String::from("secrets.reveal.approved.v1")));
        assert!(event_types.contains(&String::from("secrets.reveal.executed.v1")));

        let approval_event = messages
            .iter()
            .find(|message| message.payload.header.event_type == "secrets.reveal.approved.v1")
            .unwrap_or_else(|| panic!("missing approval event"));
        if let EventPayload::Service(event) = &approval_event.payload.payload {
            let details = event
                .details
                .as_object()
                .unwrap_or_else(|| panic!("expected object details"));
            assert_eq!(event.resource_kind, "secret_reveal_grant");
            assert_eq!(event.resource_id, grant.id.to_string());
            assert_eq!(event.action, "approved");
            assert_eq!(
                details.get("secret_id"),
                Some(&serde_json::json!(secret_id))
            );
            assert_eq!(
                details.get("secret_name"),
                Some(&serde_json::json!("grant-secret"))
            );
            assert_eq!(details.get("secret_version"), Some(&serde_json::json!(1)));
            assert_eq!(
                details.get("grant_kind"),
                Some(&serde_json::json!("approval"))
            );
            assert_eq!(
                details.get("reason"),
                Some(&serde_json::json!("breakglass validation"))
            );
            assert!(matches!(
                details.get("lease_seconds"),
                Some(value) if value.is_null()
            ));
            assert!(matches!(
                details.get("expires_at"),
                Some(value) if value.is_null()
            ));
            assert!(!details.contains_key("value"));
        } else {
            panic!("expected service payload");
        }

        let reveal_event = messages
            .iter()
            .find(|message| message.payload.header.event_type == "secrets.reveal.executed.v1")
            .unwrap_or_else(|| panic!("missing reveal event"));
        if let EventPayload::Service(event) = &reveal_event.payload.payload {
            let details = event
                .details
                .as_object()
                .unwrap_or_else(|| panic!("expected object details"));
            assert_eq!(event.resource_kind, "secret");
            assert_eq!(event.resource_id, secret_id);
            assert_eq!(event.action, "revealed");
            assert_eq!(
                details.get("secret_name"),
                Some(&serde_json::json!("grant-secret"))
            );
            assert_eq!(details.get("secret_version"), Some(&serde_json::json!(1)));
            assert_eq!(
                details.get("authorization_kind"),
                Some(&serde_json::json!("approval"))
            );
            assert_eq!(
                details.get("authorization_id"),
                Some(&serde_json::json!(grant.id.to_string()))
            );
            assert!(matches!(
                details.get("lease_expires_at"),
                Some(value) if value.is_null()
            ));
            assert_eq!(
                details.get("grant_reveal_count"),
                Some(&serde_json::json!(1))
            );
            assert!(!details.contains_key("value"));
        } else {
            panic!("expected service payload");
        }

        let audit_log = read_service_file(&temp, "audit.log");
        assert!(audit_log.contains("secrets.reveal.approved.v1"));
        assert!(audit_log.contains("secrets.reveal.executed.v1"));
        assert!(!audit_log.contains("grant-value"));
        let outbox = read_service_file(&temp, "outbox.json");
        assert!(outbox.contains("secrets.reveal.approved.v1"));
        assert!(outbox.contains("secrets.reveal.executed.v1"));
        assert!(!outbox.contains("grant-value"));
    }

    #[tokio::test]
    async fn lease_backed_reveal_can_be_reused_until_expiry_and_emits_events() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();
        let secret_id =
            create_secret_and_get_id(&service, "lease-secret", "lease-value", &context).await;

        let grant = service
            .issue_secret_reveal_lease(&secret_id, 60, "short lived access", &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(grant.grant_kind, SecretRevealGrantKind::Lease);
        assert!(grant.expires_at.is_some());

        let _first = service
            .reveal_secret_with_grant(&secret_id, grant.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _second = service
            .reveal_secret_with_grant(&secret_id, grant.id.as_str(), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_grant = service
            .reveal_grants
            .get(grant.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing lease reveal grant"));
        assert_eq!(stored_grant.value.reveal_count, 2);
        assert!(stored_grant.value.last_revealed_at.is_some());

        let messages = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 3);
        let lease_event = messages
            .iter()
            .find(|message| message.payload.header.event_type == "secrets.reveal.leased.v1")
            .unwrap_or_else(|| panic!("missing lease grant event"));
        if let EventPayload::Service(event) = &lease_event.payload.payload {
            let details = event
                .details
                .as_object()
                .unwrap_or_else(|| panic!("expected object details"));
            assert_eq!(event.resource_kind, "secret_reveal_grant");
            assert_eq!(event.resource_id, grant.id.to_string());
            assert_eq!(event.action, "leased");
            assert_eq!(
                details.get("secret_id"),
                Some(&serde_json::json!(secret_id))
            );
            assert_eq!(
                details.get("secret_name"),
                Some(&serde_json::json!("lease-secret"))
            );
            assert_eq!(details.get("secret_version"), Some(&serde_json::json!(1)));
            assert_eq!(details.get("grant_kind"), Some(&serde_json::json!("lease")));
            assert_eq!(
                details.get("reason"),
                Some(&serde_json::json!("short lived access"))
            );
            assert_eq!(details.get("lease_seconds"), Some(&serde_json::json!(60)));
            assert_eq!(
                details.get("expires_at"),
                Some(&serde_json::json!(grant.expires_at))
            );
            assert!(!details.contains_key("value"));
        } else {
            panic!("expected service payload");
        }

        let mut reveal_counts = messages
            .iter()
            .filter(|message| message.payload.header.event_type == "secrets.reveal.executed.v1")
            .map(|message| {
                if let EventPayload::Service(event) = &message.payload.payload {
                    let details = event
                        .details
                        .as_object()
                        .unwrap_or_else(|| panic!("expected object details"));
                    assert_eq!(event.resource_kind, "secret");
                    assert_eq!(event.resource_id, secret_id);
                    assert_eq!(event.action, "revealed");
                    assert_eq!(
                        details.get("secret_name"),
                        Some(&serde_json::json!("lease-secret"))
                    );
                    assert_eq!(details.get("secret_version"), Some(&serde_json::json!(1)));
                    assert_eq!(
                        details.get("authorization_kind"),
                        Some(&serde_json::json!("lease"))
                    );
                    assert_eq!(
                        details.get("authorization_id"),
                        Some(&serde_json::json!(grant.id.to_string()))
                    );
                    assert_eq!(
                        details.get("lease_expires_at"),
                        Some(&serde_json::json!(grant.expires_at))
                    );
                    assert!(!details.contains_key("value"));
                    details
                        .get("grant_reveal_count")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or_else(|| panic!("missing reveal count"))
                } else {
                    panic!("expected service payload");
                }
            })
            .collect::<Vec<_>>();
        reveal_counts.sort_unstable();
        assert_eq!(reveal_counts, vec![1, 2]);

        let audit_log = read_service_file(&temp, "audit.log");
        assert!(audit_log.contains("secrets.reveal.leased.v1"));
        assert!(audit_log.contains("secrets.reveal.executed.v1"));
        assert!(!audit_log.contains("lease-value"));
        let outbox = read_service_file(&temp, "outbox.json");
        assert!(outbox.contains("secrets.reveal.leased.v1"));
        assert!(outbox.contains("secrets.reveal.executed.v1"));
        assert!(!outbox.contains("lease-value"));
    }

    #[tokio::test]
    async fn routed_approval_and_grant_reveal_surfaces_reuse_secret_reveal_events() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();
        let secret_id = create_secret_and_get_id(
            &service,
            "route-grant-secret",
            "route-grant-value",
            &context,
        )
        .await;

        let approval_body = serde_json::to_string(&CreateSecretRevealApprovalRequest {
            reason: String::from("routed breakglass"),
        })
        .unwrap_or_else(|error| panic!("{error}"));
        let approval_response = dispatch_request(
            &service,
            Method::POST,
            &format!("/secrets/items/{secret_id}/reveal/approvals"),
            Some(&approval_body),
            context.clone(),
        )
        .await;
        assert_eq!(approval_response.status(), StatusCode::CREATED);
        let grant: SecretRevealGrantRecord = response_json(approval_response).await;
        assert_eq!(grant.grant_kind, SecretRevealGrantKind::Approval);
        assert_eq!(grant.reason, "routed breakglass");

        let reveal_response = dispatch_request(
            &service,
            Method::POST,
            &format!("/secrets/items/{secret_id}/reveal/grants/{}", grant.id),
            None,
            context.clone(),
        )
        .await;
        assert_eq!(reveal_response.status(), StatusCode::OK);
        let revealed: serde_json::Value = response_json(reveal_response).await;
        assert_eq!(revealed["value"], "route-grant-value");

        let stored_grant = service
            .reveal_grants
            .get(grant.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing routed reveal grant"));
        assert_eq!(stored_grant.value.reveal_count, 1);
        assert_eq!(
            stored_grant.value.last_revealed_by.as_deref(),
            Some("bootstrap_admin")
        );

        let messages = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 2);
        let event_types = messages
            .iter()
            .map(|message| message.payload.header.event_type.clone())
            .collect::<Vec<_>>();
        assert!(event_types.contains(&String::from("secrets.reveal.approved.v1")));
        assert!(event_types.contains(&String::from("secrets.reveal.executed.v1")));

        let approval_event = messages
            .iter()
            .find(|message| message.payload.header.event_type == "secrets.reveal.approved.v1")
            .unwrap_or_else(|| panic!("missing routed approval event"));
        if let EventPayload::Service(event) = &approval_event.payload.payload {
            assert_eq!(event.resource_kind, "secret_reveal_grant");
            assert_eq!(event.resource_id, grant.id.to_string());
            assert_eq!(event.action, "approved");
        } else {
            panic!("expected service payload");
        }

        let reveal_event = messages
            .iter()
            .find(|message| message.payload.header.event_type == "secrets.reveal.executed.v1")
            .unwrap_or_else(|| panic!("missing routed reveal event"));
        if let EventPayload::Service(event) = &reveal_event.payload.payload {
            assert_eq!(event.resource_kind, "secret");
            assert_eq!(event.resource_id, secret_id);
            assert_eq!(event.action, "revealed");
            assert_eq!(event.details["authorization_kind"], "approval");
            assert_eq!(event.details["authorization_id"], grant.id.to_string());
        } else {
            panic!("expected service payload");
        }

        let audit_log = read_service_file(&temp, "audit.log");
        assert!(audit_log.contains("secrets.reveal.approved.v1"));
        assert!(audit_log.contains("secrets.reveal.executed.v1"));
        assert!(!audit_log.contains("route-grant-value"));
        let outbox = read_service_file(&temp, "outbox.json");
        assert!(outbox.contains("secrets.reveal.approved.v1"));
        assert!(outbox.contains("secrets.reveal.executed.v1"));
        assert!(!outbox.contains("route-grant-value"));
    }

    #[tokio::test]
    async fn routed_lease_and_grant_reveal_surfaces_preserve_reuse_and_durable_evidence() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();
        let secret_id = create_secret_and_get_id(
            &service,
            "route-lease-secret",
            "route-lease-value",
            &context,
        )
        .await;

        let lease_body = serde_json::to_string(&CreateSecretRevealLeaseRequest {
            reason: String::from("routed short access"),
            lease_seconds: 30,
        })
        .unwrap_or_else(|error| panic!("{error}"));
        let lease_response = dispatch_request(
            &service,
            Method::POST,
            &format!("/secrets/items/{secret_id}/reveal/leases"),
            Some(&lease_body),
            context.clone(),
        )
        .await;
        assert_eq!(lease_response.status(), StatusCode::CREATED);
        let grant: SecretRevealGrantRecord = response_json(lease_response).await;
        assert_eq!(grant.grant_kind, SecretRevealGrantKind::Lease);
        assert_eq!(grant.reason, "routed short access");
        assert!(grant.expires_at.is_some());

        for _ in 0..2 {
            let reveal_response = dispatch_request(
                &service,
                Method::POST,
                &format!("/secrets/items/{secret_id}/reveal/grants/{}", grant.id),
                None,
                context.clone(),
            )
            .await;
            assert_eq!(reveal_response.status(), StatusCode::OK);
            let revealed: serde_json::Value = response_json(reveal_response).await;
            assert_eq!(revealed["value"], "route-lease-value");
        }

        let stored_grant = service
            .reveal_grants
            .get(grant.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing routed lease grant"));
        assert_eq!(stored_grant.value.reveal_count, 2);

        let messages = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 3);
        let event_types = messages
            .iter()
            .map(|message| message.payload.header.event_type.clone())
            .collect::<Vec<_>>();
        assert!(event_types.contains(&String::from("secrets.reveal.leased.v1")));
        let reveal_counts = messages
            .iter()
            .filter(|message| message.payload.header.event_type == "secrets.reveal.executed.v1")
            .map(|message| {
                if let EventPayload::Service(event) = &message.payload.payload {
                    assert_eq!(event.resource_kind, "secret");
                    assert_eq!(event.resource_id, secret_id);
                    assert_eq!(event.details["authorization_kind"], "lease");
                    assert_eq!(event.details["authorization_id"], grant.id.to_string());
                    event.details["grant_reveal_count"]
                        .as_u64()
                        .unwrap_or_else(|| panic!("missing routed lease reveal count"))
                } else {
                    panic!("expected service payload");
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(reveal_counts.len(), 2);
        assert!(reveal_counts.contains(&1));
        assert!(reveal_counts.contains(&2));

        let audit_log = read_service_file(&temp, "audit.log");
        assert!(audit_log.contains("secrets.reveal.leased.v1"));
        assert!(audit_log.contains("secrets.reveal.executed.v1"));
        assert!(!audit_log.contains("route-lease-value"));
        let outbox = read_service_file(&temp, "outbox.json");
        assert!(outbox.contains("secrets.reveal.leased.v1"));
        assert!(outbox.contains("secrets.reveal.executed.v1"));
        assert!(!outbox.contains("route-lease-value"));
    }

    #[tokio::test]
    async fn concurrent_creates_do_not_duplicate_versions_for_same_name() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let service = std::sync::Arc::new(service);

        let make_secret = |svc: std::sync::Arc<SecretsService>, value: &'static str| async move {
            let context = operator_context();
            let response = svc
                .create_secret(
                    CreateSecretRequest {
                        name: String::from("race-secret"),
                        value: String::from(value),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let bytes = http_body_util::BodyExt::collect(response.into_body())
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .to_bytes();
            let payload: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"));
            payload["version"].as_u64().unwrap() as u32
        };

        let (v1, v2) = tokio::join!(
            make_secret(service.clone(), "first"),
            make_secret(service.clone(), "second")
        );
        assert_ne!(v1, v2, "versions must not duplicate");
        let mut versions = vec![v1, v2];
        versions.sort_unstable();
        assert_eq!(versions, vec![1, 2]);
    }

    #[tokio::test]
    async fn summary_reflects_persisted_active_secret_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = SecretsService::open(temp.path(), master_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = operator_context();

        let first = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("db-password"),
                    value: String::from("v1"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_payload = http_body_util::BodyExt::collect(first.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_response: serde_json::Value =
            serde_json::from_slice(&first_payload).unwrap_or_else(|error| panic!("{error}"));
        let first_id = first_response["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing first secret id"))
            .to_owned();

        let _ = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("db-password"),
                    value: String::from("v2"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let third = service
            .create_secret(
                CreateSecretRequest {
                    name: String::from("api-token"),
                    value: String::from("token-value"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let third_payload = http_body_util::BodyExt::collect(third.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let third_response: serde_json::Value =
            serde_json::from_slice(&third_payload).unwrap_or_else(|error| panic!("{error}"));
        let third_id = third_response["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing third secret id"))
            .to_owned();

        service
            .secrets
            .soft_delete(&first_id, Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .secrets
            .soft_delete(&third_id, Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary_response = service
            .summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let summary_payload = http_body_util::BodyExt::collect(summary_response.into_body())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let summary: serde_json::Value =
            serde_json::from_slice(&summary_payload).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary["secret_count"], 1);
        assert_eq!(summary["unique_secret_name_count"], 1);
        assert_eq!(summary["highest_version"], 2);
        assert_eq!(summary["latest_version_by_name"]["db-password"], 2);
        assert!(summary["latest_version_by_name"]["api-token"].is_null());
        assert_eq!(summary["ownership_scope_totals"]["project"], 1);
    }
}
