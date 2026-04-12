//! Identity and access service.
//!
//! Purpose:
//! - Own users, sessions, and API keys.
//! - Enforce basic authentication state, password hashing, and user suspension.
//! - Emit audit events for every mutating action.

use std::collections::{BTreeMap, BTreeSet, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use uhost_api::{ApiBody, empty_response, json_response, parse_json, path_segments, with_etag};
use uhost_core::{
    ErrorCode, PlatformError, PrincipalIdentity, PrincipalKind, RequestContext, Result,
    SecretBytes, SecretString, base64url_encode, hash_password, random_bytes, seal_secret,
    sha256_hex, validate_email,
};
use uhost_runtime::{AuthorizationFuture, BearerTokenAuthorizer, HttpService};
use uhost_store::{
    AuditLog, DocumentStore, DurableEventRelay, MetadataCollection, MetadataJournal,
    MetadataWriteBatch, RelayPublishRequest, StoredDocument,
};
use uhost_types::{
    ApiKeyId, AuditActor, AuditId, EventHeader, EventPayload, OwnershipScope, PlatformEvent,
    ProjectId, ResourceLifecycleState, ResourceMetadata, ServiceEvent, SessionId, UserId,
    WorkloadId, WorkloadIdentityId,
};

/// User record owned by the identity service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    /// Typed user identifier.
    pub id: UserId,
    /// Canonical lowercase email address.
    pub email: String,
    /// Display name shown in operator surfaces.
    pub display_name: String,
    /// Argon2 password hash.
    pub password_hash: String,
    /// Whether MFA is enabled for the account.
    pub mfa_enabled: bool,
    /// Whether the account is suspended.
    pub suspended: bool,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// Session identifier.
    pub id: SessionId,
    /// Owning user.
    pub user_id: UserId,
    /// Issued timestamp.
    pub issued_at: OffsetDateTime,
    /// Expiration timestamp.
    pub expires_at: OffsetDateTime,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// API key record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyCredentialRecord {
    /// Monotonic credential version for rotation and lifecycle reporting.
    pub version: u32,
    /// Non-secret credential preview shown to operators.
    pub secret_preview: String,
    /// SHA-256 hash of the full secret.
    pub secret_hash: String,
    /// Issue timestamp.
    pub issued_at: OffsetDateTime,
}

/// API key record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    /// Key identifier.
    pub id: ApiKeyId,
    /// Owning user.
    pub user_id: UserId,
    /// Human-readable key name.
    pub name: String,
    /// Monotonic credential version for rotation and lifecycle reporting.
    #[serde(default = "initial_credential_version")]
    pub secret_version: u32,
    /// Non-secret preview for operators.
    pub secret_preview: String,
    /// SHA-256 hash of the full secret.
    pub secret_hash: String,
    /// Issue timestamp for the current credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<OffsetDateTime>,
    /// Rotation status.
    pub active: bool,
    /// Superseded credential material retained for lifecycle reporting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_credentials: Vec<ApiKeyCredentialRecord>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Sealed workload credential material owned by the identity service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentityCredentialRecord {
    /// Monotonic credential version for future rotation flows.
    pub version: u32,
    /// Non-secret credential preview shown to operators.
    pub secret_preview: String,
    /// Sealed bearer token material.
    pub secret_ciphertext: String,
    /// SHA-256 fingerprint of the bearer token.
    pub secret_hash: String,
    /// Issue timestamp.
    pub issued_at: OffsetDateTime,
    /// Expiration timestamp.
    pub expires_at: OffsetDateTime,
}

/// Durable workload identity foundation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadIdentityRecord {
    /// Workload identity identifier.
    pub id: WorkloadIdentityId,
    /// Explicit principal envelope for this workload identity.
    pub principal: PrincipalIdentity,
    /// Human-readable display name.
    pub display_name: String,
    /// Optional owning project identifier.
    pub project_id: Option<ProjectId>,
    /// Optional workload linkage identifier.
    pub workload_id: Option<WorkloadId>,
    /// Audience restrictions carried forward to later federation work.
    pub audiences: Vec<String>,
    /// Whether the identity is active.
    pub active: bool,
    /// Current issued credential material.
    pub credential: WorkloadIdentityCredentialRecord,
    /// Superseded credential material retained for lifecycle reporting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub previous_credentials: Vec<WorkloadIdentityCredentialRecord>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateUserRequest {
    email: String,
    display_name: String,
    password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateUsersBulkRequest {
    users: Vec<CreateUserRequest>,
    fail_fast: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BulkUserError {
    email: String,
    code: String,
    message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateUsersBulkResponse {
    attempted: usize,
    created_count: usize,
    failed_count: usize,
    created: Vec<UserView>,
    failed: Vec<BulkUserError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSessionRequest {
    email: String,
    password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateApiKeyRequest {
    user_id: String,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateWorkloadIdentityRequest {
    subject: String,
    display_name: String,
    project_id: Option<String>,
    workload_id: Option<String>,
    #[serde(default)]
    audiences: Vec<String>,
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UserView {
    id: String,
    email: String,
    display_name: String,
    mfa_enabled: bool,
    suspended: bool,
    metadata: ResourceMetadata,
}

impl From<&UserRecord> for UserView {
    fn from(value: &UserRecord) -> Self {
        Self {
            id: value.id.to_string(),
            email: value.email.clone(),
            display_name: value.display_name.clone(),
            mfa_enabled: value.mfa_enabled,
            suspended: value.suspended,
            metadata: value.metadata.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkloadCredentialView {
    version: u32,
    secret_preview: String,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkloadIdentityView {
    id: String,
    principal: PrincipalIdentity,
    display_name: String,
    project_id: Option<String>,
    workload_id: Option<String>,
    audiences: Vec<String>,
    active: bool,
    credential: WorkloadCredentialView,
    metadata: ResourceMetadata,
}

impl From<&WorkloadIdentityRecord> for WorkloadIdentityView {
    fn from(value: &WorkloadIdentityRecord) -> Self {
        Self {
            id: value.id.to_string(),
            principal: value.principal.clone(),
            display_name: value.display_name.clone(),
            project_id: value.project_id.as_ref().map(ToString::to_string),
            workload_id: value.workload_id.as_ref().map(ToString::to_string),
            audiences: value.audiences.clone(),
            active: value.active,
            credential: WorkloadCredentialView {
                version: value.credential.version,
                secret_preview: value.credential.secret_preview.clone(),
                issued_at: value.credential.issued_at,
                expires_at: value.credential.expires_at,
            },
            metadata: value.metadata.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateWorkloadIdentityResponse {
    identity: WorkloadIdentityView,
    token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentitySummary {
    users: IdentityUserSummary,
    sessions: IdentitySessionSummary,
    api_keys: IdentityApiKeySummary,
    workload_identities: IdentityWorkloadIdentitySummary,
    credential_lifecycle: IdentityCredentialLifecycleSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityUserSummary {
    total: usize,
    active: usize,
    suspended: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentitySessionSummary {
    total: usize,
    active: usize,
    expired: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityApiKeySummary {
    total: usize,
    active: usize,
    inactive: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityWorkloadIdentitySummary {
    total: usize,
    active: usize,
    inactive: usize,
    unscoped: usize,
    by_project: Vec<ProjectWorkloadIdentitySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ProjectWorkloadIdentitySummary {
    project_id: String,
    total: usize,
    active: usize,
    inactive: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdentityCredentialLifecycleKind {
    Session,
    ApiKey,
    WorkloadToken,
    SecretVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdentityCredentialLifecycleState {
    Active,
    Expiring,
    Expired,
    Inactive,
    Revoked,
    SuspendedOwner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IdentityCredentialSecretSourceKind {
    ApiKey,
    WorkloadToken,
}

impl IdentityCredentialSecretSourceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::WorkloadToken => "workload_token",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityCredentialLifecycleSummary {
    total: usize,
    by_kind: Vec<IdentityCredentialLifecycleKindSummary>,
    by_state: Vec<IdentityCredentialLifecycleStateSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityCredentialLifecycleKindSummary {
    kind: IdentityCredentialLifecycleKind,
    total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityCredentialLifecycleStateSummary {
    state: IdentityCredentialLifecycleState,
    total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityCredentialLifecycleReport {
    generated_at: OffsetDateTime,
    summary: IdentityCredentialLifecycleSummary,
    entries: Vec<IdentityCredentialLifecycleEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IdentityCredentialLifecycleEntry {
    kind: IdentityCredentialLifecycleKind,
    id: String,
    state: IdentityCredentialLifecycleState,
    ownership_scope: OwnershipScope,
    owner_id: Option<String>,
    issued_at: OffsetDateTime,
    expires_at: Option<OffsetDateTime>,
    principal_subject: Option<String>,
    source_kind: Option<IdentityCredentialSecretSourceKind>,
    source_id: Option<String>,
    version: Option<u32>,
    secret_preview: Option<String>,
}

const DEFAULT_WORKLOAD_IDENTITY_TTL_SECONDS: u64 = 3_600;
const MAX_WORKLOAD_IDENTITY_TTL_SECONDS: u64 = 86_400;
const INITIAL_DOCUMENT_VERSION: u64 = 1;
const USER_ADMISSION_GUARD_SHARDS: usize = 64;

const fn initial_credential_version() -> u32 {
    1
}

fn validate_nonempty_trimmed(value: String, field_name: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field_name} may not be empty"
        )));
    }

    Ok(trimmed.to_owned())
}

async fn hash_user_password(password: String) -> Result<String> {
    tokio::task::spawn_blocking(move || hash_password(&SecretString::new(password)))
        .await
        .map_err(|error| {
            PlatformError::unavailable("password hashing worker failed")
                .with_detail(error.to_string())
        })?
}

async fn verify_user_password(password: String, encoded_hash: String) -> Result<bool> {
    tokio::task::spawn_blocking(move || {
        uhost_core::verify_password(&SecretString::new(password), &encoded_hash)
    })
    .await
    .map_err(|error| {
        PlatformError::unavailable("password verification worker failed")
            .with_detail(error.to_string())
    })?
}

fn user_admission_guard_index(email: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    email.hash(&mut hasher);
    (hasher.finish() as usize) % USER_ADMISSION_GUARD_SHARDS
}

fn resource_metadata_is_revoked(metadata: &ResourceMetadata) -> bool {
    metadata.deleted_at.is_some() || metadata.lifecycle == ResourceLifecycleState::Deleted
}

fn credential_window_state(
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    now: OffsetDateTime,
) -> IdentityCredentialLifecycleState {
    if issued_at > now {
        return IdentityCredentialLifecycleState::Inactive;
    }
    if expires_at <= now {
        return IdentityCredentialLifecycleState::Expired;
    }

    let lifetime_seconds = (expires_at - issued_at).whole_seconds().max(1);
    let remaining_seconds = (expires_at - now).whole_seconds().max(0);
    let expiring_threshold_seconds = (lifetime_seconds / 4).max(1);
    if remaining_seconds <= expiring_threshold_seconds {
        return IdentityCredentialLifecycleState::Expiring;
    }

    IdentityCredentialLifecycleState::Active
}

fn secret_version_entry_id(
    source_kind: IdentityCredentialSecretSourceKind,
    source_id: &str,
    version: u32,
) -> String {
    format!("{}/{source_id}/versions/{version}", source_kind.as_str())
}

fn user_principal_subject(user_id: &UserId) -> String {
    format!("user:{user_id}")
}

fn current_api_key_issued_at(record: &ApiKeyRecord) -> OffsetDateTime {
    record.issued_at.unwrap_or(record.metadata.created_at)
}

fn current_api_key_credential(record: &ApiKeyRecord) -> ApiKeyCredentialRecord {
    ApiKeyCredentialRecord {
        version: record.secret_version,
        secret_preview: record.secret_preview.clone(),
        secret_hash: record.secret_hash.clone(),
        issued_at: current_api_key_issued_at(record),
    }
}

fn api_key_response(record: &ApiKeyRecord) -> serde_json::Value {
    serde_json::json!({
        "id": record.id,
        "user_id": record.user_id,
        "name": record.name,
        "version": record.secret_version,
        "secret_preview": record.secret_preview,
        "issued_at": current_api_key_issued_at(record),
        "active": record.active,
        "metadata": record.metadata,
    })
}

fn api_key_secret_response(record: &ApiKeyRecord, secret: &str) -> serde_json::Value {
    let mut payload = api_key_response(record);
    payload["secret"] = serde_json::Value::String(secret.to_owned());
    payload
}

fn next_credential_version(version: u32, resource_kind: &str) -> Result<u32> {
    version.checked_add(1).ok_or_else(|| {
        PlatformError::conflict(format!(
            "{resource_kind} exceeded the maximum supported credential version"
        ))
    })
}

fn workload_identity_credential_ttl_seconds(
    credential: &WorkloadIdentityCredentialRecord,
) -> Result<i64> {
    let ttl_seconds = (credential.expires_at - credential.issued_at).whole_seconds();
    if ttl_seconds <= 0 {
        return Err(PlatformError::conflict(
            "workload identity credential has no remaining rotation lifetime template",
        ));
    }
    Ok(ttl_seconds)
}

fn user_owner_is_revoked(owner: Option<&StoredDocument<UserRecord>>) -> bool {
    match owner {
        Some(user) => user.deleted || resource_metadata_is_revoked(&user.value.metadata),
        None => true,
    }
}

fn user_owner_is_suspended(owner: Option<&StoredDocument<UserRecord>>) -> bool {
    matches!(owner, Some(user) if user.value.suspended)
}

fn normalize_workload_identity_subject(value: String) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("subject may not be empty"));
    }

    let subject = if let Some(subject) = normalized.strip_prefix("svc:") {
        subject
    } else if let Some(subject) = normalized.strip_prefix("workload:") {
        subject
    } else {
        return Err(PlatformError::invalid(
            "subject must start with `svc:` or `workload:`",
        ));
    };

    if subject.is_empty() {
        return Err(PlatformError::invalid(
            "subject must include a name after the prefix",
        ));
    }

    if !subject.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.')
    }) {
        return Err(PlatformError::invalid(
            "subject contains unsupported characters",
        ));
    }

    Ok(normalized)
}

fn normalize_workload_identity_audiences(audiences: Vec<String>) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();

    for audience in audiences {
        let trimmed = audience.trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            return Err(PlatformError::invalid(
                "audiences may not contain empty values",
            ));
        }
        if trimmed.len() > 128 {
            return Err(PlatformError::invalid("audience exceeds 128 bytes"));
        }
        if !trimmed.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.' | ':')
        }) {
            return Err(PlatformError::invalid(
                "audience contains unsupported characters",
            ));
        }

        if seen.insert(trimmed.clone()) {
            normalized.push(trimmed);
        }
    }

    Ok(normalized)
}

fn normalize_workload_identity_ttl_seconds(ttl_seconds: Option<u64>) -> Result<u64> {
    let ttl_seconds = ttl_seconds.unwrap_or(DEFAULT_WORKLOAD_IDENTITY_TTL_SECONDS);
    if ttl_seconds == 0 {
        return Err(PlatformError::invalid(
            "ttl_seconds must be greater than zero",
        ));
    }
    if ttl_seconds > MAX_WORKLOAD_IDENTITY_TTL_SECONDS {
        return Err(PlatformError::invalid(format!(
            "ttl_seconds exceeds maximum of {MAX_WORKLOAD_IDENTITY_TTL_SECONDS}",
        )));
    }
    Ok(ttl_seconds)
}

fn parse_optional_project_id(project_id: Option<String>) -> Result<Option<ProjectId>> {
    project_id
        .map(|value| {
            ProjectId::parse(value).map_err(|error| {
                PlatformError::invalid("invalid project_id").with_detail(error.to_string())
            })
        })
        .transpose()
}

fn parse_optional_workload_id(workload_id: Option<String>) -> Result<Option<WorkloadId>> {
    workload_id
        .map(|value| {
            WorkloadId::parse(value).map_err(|error| {
                PlatformError::invalid("invalid workload_id").with_detail(error.to_string())
            })
        })
        .transpose()
}

fn workload_identity_ownership(project_id: Option<&ProjectId>) -> (OwnershipScope, Option<String>) {
    match project_id {
        Some(project_id) => (OwnershipScope::Project, Some(project_id.to_string())),
        None => (OwnershipScope::Platform, None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UserEmailIndexRecord {
    email: String,
    user_id: UserId,
    created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ApiKeySecretHashIndexRecord {
    secret_hash: String,
    api_key_id: ApiKeyId,
    created_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WorkloadIdentitySubjectIndexRecord {
    subject: String,
    workload_identity_id: WorkloadIdentityId,
    created_at: OffsetDateTime,
}

/// Runtime identity service.
#[derive(Debug, Clone)]
pub struct IdentityService {
    users: MetadataCollection<UserRecord>,
    users_by_email: MetadataCollection<UserEmailIndexRecord>,
    sessions: DocumentStore<SessionRecord>,
    api_keys: DocumentStore<ApiKeyRecord>,
    api_keys_by_secret_hash: MetadataCollection<ApiKeySecretHashIndexRecord>,
    workload_identities: DocumentStore<WorkloadIdentityRecord>,
    workload_identities_by_subject: MetadataCollection<WorkloadIdentitySubjectIndexRecord>,
    audit_log: AuditLog,
    outbox: DurableEventRelay<PlatformEvent>,
    write_journal: MetadataJournal,
    state_root: PathBuf,
    workload_identity_key: Option<SecretBytes>,
    user_admission_guards: Vec<Arc<Mutex<()>>>,
    workload_identity_guard: Arc<Mutex<()>>,
}

impl IdentityService {
    /// Open the identity service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("identity");
        let users = MetadataCollection::open_local(root.join("users.json")).await?;
        let users_by_email =
            MetadataCollection::open_local(root.join("users_by_email.json")).await?;
        Self::open_with_user_metadata(root, users, users_by_email, None).await
    }

    /// Open the identity service state with an explicit sealing key for workload credentials.
    pub async fn open_with_master_key(
        state_root: impl AsRef<Path>,
        master_key: SecretBytes,
    ) -> Result<Self> {
        let root = state_root.as_ref().join("identity");
        let users = MetadataCollection::open_local(root.join("users.json")).await?;
        let users_by_email =
            MetadataCollection::open_local(root.join("users_by_email.json")).await?;
        Self::open_with_user_metadata(root, users, users_by_email, Some(master_key)).await
    }

    async fn open_with_user_metadata(
        root: PathBuf,
        users: MetadataCollection<UserRecord>,
        users_by_email: MetadataCollection<UserEmailIndexRecord>,
        workload_identity_key: Option<SecretBytes>,
    ) -> Result<Self> {
        let service = Self {
            users,
            users_by_email,
            sessions: DocumentStore::open(root.join("sessions.json")).await?,
            api_keys: DocumentStore::open(root.join("api_keys.json")).await?,
            api_keys_by_secret_hash: MetadataCollection::open_local(
                root.join("api_keys_by_secret_hash.json"),
            )
            .await?,
            workload_identities: DocumentStore::open(root.join("workload_identities.json")).await?,
            workload_identities_by_subject: MetadataCollection::open_local(
                root.join("workload_identities_by_subject.json"),
            )
            .await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableEventRelay::open(root.join("outbox.json")).await?,
            write_journal: MetadataJournal::open(root.join("journal")).await?,
            state_root: root,
            workload_identity_key,
            user_admission_guards: (0..USER_ADMISSION_GUARD_SHARDS)
                .map(|_| Arc::new(Mutex::new(())))
                .collect(),
            workload_identity_guard: Arc::new(Mutex::new(())),
        };
        service.reconcile_email_index().await?;
        service.reconcile_api_key_secret_hash_index().await?;
        service.reconcile_workload_identity_subject_index().await?;
        Ok(service)
    }

    async fn reconcile_email_index(&self) -> Result<()> {
        let users = self
            .users
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let current_index = self.users_by_email.list().await?;
        let current_by_email = current_index
            .iter()
            .map(|(email, record)| (email.clone(), record.clone()))
            .collect::<BTreeMap<String, StoredDocument<UserEmailIndexRecord>>>();
        let mut active_emails = BTreeSet::new();
        for user in users {
            active_emails.insert(user.email.clone());
            let target = UserEmailIndexRecord {
                email: user.email.clone(),
                user_id: user.id,
                created_at: OffsetDateTime::now_utc(),
            };
            let email_key = target.email.clone();
            if let Some(existing) = current_by_email.get(&target.email) {
                self.users_by_email
                    .upsert(&email_key, target, Some(existing.version))
                    .await?;
            } else {
                self.users_by_email.create(&email_key, target).await?;
            }
        }
        for (email, record) in current_by_email {
            if !record.deleted && !active_emails.contains(&email) {
                self.users_by_email
                    .soft_delete(&email, Some(record.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn reconcile_workload_identity_subject_index(&self) -> Result<()> {
        let identities = self
            .workload_identities
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let current_index = self.workload_identities_by_subject.list().await?;
        let current_by_subject = current_index
            .iter()
            .map(|(subject, record)| (subject.clone(), record.clone()))
            .collect::<BTreeMap<String, StoredDocument<WorkloadIdentitySubjectIndexRecord>>>();
        let mut active_subjects = BTreeSet::new();
        for identity in identities {
            active_subjects.insert(identity.principal.subject.clone());
            let target = WorkloadIdentitySubjectIndexRecord {
                subject: identity.principal.subject.clone(),
                workload_identity_id: identity.id,
                created_at: OffsetDateTime::now_utc(),
            };
            let subject_key = target.subject.clone();
            if let Some(existing) = current_by_subject.get(&target.subject) {
                self.workload_identities_by_subject
                    .upsert(&subject_key, target, Some(existing.version))
                    .await?;
            } else {
                self.workload_identities_by_subject
                    .create(&subject_key, target)
                    .await?;
            }
        }
        for (subject, record) in current_by_subject {
            if !record.deleted && !active_subjects.contains(&subject) {
                self.workload_identities_by_subject
                    .soft_delete(&subject, Some(record.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn reconcile_api_key_secret_hash_index(&self) -> Result<()> {
        let api_keys = self
            .api_keys
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| {
                !record.deleted
                    && record.value.active
                    && !resource_metadata_is_revoked(&record.value.metadata)
            })
            .map(|(_, record)| record.value)
            .collect::<Vec<_>>();
        let current_index = self.api_keys_by_secret_hash.list().await?;
        let current_by_hash = current_index
            .iter()
            .map(|(secret_hash, record)| (secret_hash.clone(), record.clone()))
            .collect::<BTreeMap<String, StoredDocument<ApiKeySecretHashIndexRecord>>>();
        let mut active_hashes = BTreeSet::new();
        for api_key in api_keys {
            active_hashes.insert(api_key.secret_hash.clone());
            let target = ApiKeySecretHashIndexRecord {
                secret_hash: api_key.secret_hash.clone(),
                api_key_id: api_key.id,
                created_at: OffsetDateTime::now_utc(),
            };
            let secret_hash_key = target.secret_hash.clone();
            if let Some(existing) = current_by_hash.get(&target.secret_hash) {
                self.api_keys_by_secret_hash
                    .upsert(&secret_hash_key, target, Some(existing.version))
                    .await?;
            } else {
                self.api_keys_by_secret_hash
                    .create(&secret_hash_key, target)
                    .await?;
            }
        }
        for (secret_hash, record) in current_by_hash {
            if !record.deleted && !active_hashes.contains(&secret_hash) {
                self.api_keys_by_secret_hash
                    .soft_delete(&secret_hash, Some(record.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn queue_api_key_secret_hash_update(
        &self,
        batch: &mut MetadataWriteBatch,
        previous_hash: Option<&str>,
        next_hash: Option<&str>,
        api_key_id: &ApiKeyId,
        created_at: OffsetDateTime,
    ) -> Result<()> {
        if let Some(previous_hash) = previous_hash
            && Some(previous_hash) != next_hash
            && let Some(existing) = self.api_keys_by_secret_hash.get(previous_hash).await?
            && !existing.deleted
        {
            batch.soft_delete_metadata(
                &self.api_keys_by_secret_hash,
                previous_hash,
                Some(existing.version),
            )?;
        }

        if let Some(next_hash) = next_hash {
            let index_record = ApiKeySecretHashIndexRecord {
                secret_hash: next_hash.to_owned(),
                api_key_id: api_key_id.clone(),
                created_at,
            };
            match self.api_keys_by_secret_hash.get(next_hash).await? {
                Some(existing) if existing.deleted => batch.upsert_metadata(
                    &self.api_keys_by_secret_hash,
                    next_hash,
                    index_record,
                    Some(existing.version),
                )?,
                Some(existing) if existing.value.api_key_id != *api_key_id => {
                    return Err(PlatformError::conflict(
                        "api key secret hash already exists",
                    ));
                }
                Some(existing) => batch.upsert_metadata(
                    &self.api_keys_by_secret_hash,
                    next_hash,
                    index_record,
                    Some(existing.version),
                )?,
                None => {
                    batch.create_metadata(&self.api_keys_by_secret_hash, next_hash, index_record)?
                }
            }
        }

        Ok(())
    }

    async fn resolve_workload_identity_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<WorkloadIdentityRecord>> {
        let matches = self
            .workload_identities
            .list()
            .await?
            .into_iter()
            .filter_map(|(_, record)| {
                if record.deleted || record.value.credential.secret_hash != token_hash {
                    return None;
                }

                Some(record.value)
            })
            .collect::<Vec<_>>();

        if matches.len() != 1 {
            return Ok(None);
        }

        Ok(matches.into_iter().next())
    }

    async fn resolve_api_key_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<ApiKeyRecord>> {
        // API-key resolution fast-paths through the secret-hash index, then
        // lazily heals missing or stale index entries by scanning the primary
        // store when the index cannot prove the answer.
        if let Some(index) = self.api_keys_by_secret_hash.get(token_hash).await?
            && !index.deleted
            && let Some(api_key) = self.api_keys.get(index.value.api_key_id.as_str()).await?
            && !api_key.deleted
            && api_key.value.secret_hash == token_hash
            && api_key.value.active
            && !resource_metadata_is_revoked(&api_key.value.metadata)
        {
            return Ok(Some(api_key.value));
        }

        for (_, stored) in self.api_keys.list().await? {
            if stored.deleted
                || stored.value.secret_hash != token_hash
                || !stored.value.active
                || resource_metadata_is_revoked(&stored.value.metadata)
            {
                continue;
            }

            let api_key = stored.value;
            let index_record = ApiKeySecretHashIndexRecord {
                secret_hash: api_key.secret_hash.clone(),
                api_key_id: api_key.id.clone(),
                created_at: OffsetDateTime::now_utc(),
            };
            match self.api_keys_by_secret_hash.get(token_hash).await? {
                Some(existing) if existing.deleted => {
                    self.api_keys_by_secret_hash
                        .upsert(token_hash, index_record, Some(existing.version))
                        .await?;
                }
                Some(existing) if existing.value.api_key_id != api_key.id => {
                    self.api_keys_by_secret_hash
                        .upsert(token_hash, index_record, Some(existing.version))
                        .await?;
                }
                Some(_) => {}
                None => {
                    self.api_keys_by_secret_hash
                        .create(token_hash, index_record)
                        .await?;
                }
            }
            return Ok(Some(api_key));
        }

        Ok(None)
    }

    async fn authorize_workload_token_for_service(
        &self,
        bearer_token: &str,
        service_name: &str,
    ) -> Result<Option<PrincipalIdentity>> {
        let bearer_token = bearer_token.trim();
        if bearer_token.is_empty() {
            return Ok(None);
        }

        let service_name = service_name.trim().to_ascii_lowercase();
        if service_name.is_empty() {
            return Ok(None);
        }

        let Some(record) = self
            .resolve_workload_identity_by_token_hash(&sha256_hex(bearer_token.as_bytes()))
            .await?
        else {
            return Ok(None);
        };

        if !record.active
            || record.metadata.deleted_at.is_some()
            || record.metadata.lifecycle == ResourceLifecycleState::Deleted
        {
            return Ok(None);
        }

        let now = OffsetDateTime::now_utc();
        if record.credential.issued_at > now || record.credential.expires_at <= now {
            return Ok(None);
        }

        if record.principal.kind != PrincipalKind::Workload || record.principal.validate().is_err()
        {
            return Ok(None);
        }

        let Ok(normalized_subject) =
            normalize_workload_identity_subject(record.principal.subject.clone())
        else {
            return Ok(None);
        };
        if normalized_subject != record.principal.subject {
            return Ok(None);
        }

        if record.principal.credential_id.as_deref() != Some(record.id.as_str()) {
            return Ok(None);
        }

        let Some(subject_index) = self
            .workload_identities_by_subject
            .get(&record.principal.subject)
            .await?
        else {
            return Ok(None);
        };
        if subject_index.deleted
            || subject_index.value.workload_identity_id.as_str() != record.id.as_str()
        {
            return Ok(None);
        }

        if !record
            .audiences
            .iter()
            .any(|audience| audience == &service_name)
        {
            return Ok(None);
        }

        Ok(Some(record.principal.clone()))
    }

    async fn authorize_api_key_for_service(
        &self,
        bearer_token: &str,
        _service_name: &str,
    ) -> Result<Option<PrincipalIdentity>> {
        let bearer_token = bearer_token.trim();
        if bearer_token.is_empty() {
            return Ok(None);
        }

        let Some(record) = self
            .resolve_api_key_by_token_hash(&sha256_hex(bearer_token.as_bytes()))
            .await?
        else {
            return Ok(None);
        };

        if !record.active
            || record.metadata.deleted_at.is_some()
            || record.metadata.lifecycle == ResourceLifecycleState::Deleted
        {
            return Ok(None);
        }

        let Some(user) = self.users.get(record.user_id.as_str()).await? else {
            return Ok(None);
        };
        if user.deleted || user.value.suspended {
            return Ok(None);
        }

        Ok(Some(
            PrincipalIdentity::new(PrincipalKind::User, format!("user:{}", record.user_id))
                .with_credential_id(record.id.to_string()),
        ))
    }

    async fn authorize_bearer_token_for_service(
        &self,
        bearer_token: &str,
        service_name: &str,
    ) -> Result<Option<PrincipalIdentity>> {
        if let Some(principal) = self
            .authorize_workload_token_for_service(bearer_token, service_name)
            .await?
        {
            return Ok(Some(principal));
        }

        self.authorize_api_key_for_service(bearer_token, service_name)
            .await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<UserRecord>> {
        if let Some(index) = self.users_by_email.get(email).await?
            && !index.deleted
            && let Some(user) = self.users.get(index.value.user_id.as_str()).await?
            && !user.deleted
            && user.value.email == email
        {
            return Ok(Some(user.value));
        }

        for (_, stored) in self.users.list().await? {
            if stored.deleted || stored.value.email != email {
                continue;
            }

            let user = stored.value;
            let index_record = UserEmailIndexRecord {
                email: user.email.clone(),
                user_id: user.id.clone(),
                created_at: OffsetDateTime::now_utc(),
            };
            match self.users_by_email.get(email).await? {
                Some(existing) if existing.deleted => {
                    self.users_by_email
                        .upsert(email, index_record, Some(existing.version))
                        .await?;
                }
                Some(existing) if existing.value.user_id != user.id => {
                    self.users_by_email
                        .upsert(email, index_record, Some(existing.version))
                        .await?;
                }
                Some(_) => {}
                None => {
                    self.users_by_email.create(email, index_record).await?;
                }
            }
            return Ok(Some(user));
        }

        Ok(None)
    }

    async fn create_user(
        &self,
        request: CreateUserRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let email = validate_email(&request.email)?;
        let _guard = self.user_admission_guards[user_admission_guard_index(&email)]
            .lock()
            .await;
        let (user_view, etag, version) = self
            .create_user_record_locked(request, context)
            .await
            .map_err(|error| error.with_correlation_id(context.correlation_id.clone()))?;

        with_etag(json_response(StatusCode::CREATED, &user_view)?, &etag)
            .map_err(|error| error.with_correlation_id(context.correlation_id.clone()))
            .map(|mut response| {
                response.headers_mut().insert(
                    "x-record-version",
                    http::HeaderValue::from_str(&version.to_string())
                        .unwrap_or_else(|_| http::HeaderValue::from_static("1")),
                );
                response
            })
    }

    async fn create_users_bulk(
        &self,
        request: CreateUsersBulkRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        if request.users.is_empty() {
            return Err(PlatformError::invalid("users list may not be empty"));
        }
        if request.users.len() > 1_000 {
            return Err(PlatformError::invalid(
                "users list exceeds maximum batch size of 1000",
            ));
        }

        let fail_fast = request.fail_fast.unwrap_or(false);
        let mut created = Vec::new();
        let mut failed = Vec::new();
        let mut seen_emails = BTreeSet::new();
        let mut users = Vec::new();
        let mut guard_indices = BTreeSet::new();
        for user in request.users {
            let normalized_email = validate_email(&user.email)?;
            if !seen_emails.insert(normalized_email.clone()) {
                failed.push(BulkUserError {
                    email: normalized_email,
                    code: String::from("conflict"),
                    message: String::from("duplicate email in bulk payload"),
                });
                if fail_fast {
                    break;
                }
                continue;
            }
            guard_indices.insert(user_admission_guard_index(&normalized_email));
            users.push((user, normalized_email));
        }
        // Lock unique email shards in sorted order before any writes so
        // duplicate-address admission serializes cleanly without lock-order
        // inversion across concurrent bulk requests.
        let mut admission_guards = Vec::with_capacity(guard_indices.len());
        for index in guard_indices {
            admission_guards.push(self.user_admission_guards[index].clone().lock_owned().await);
        }
        for (user, normalized_email) in users {
            match self.create_user_record_locked(user, context).await {
                Ok((user_view, _, _)) => {
                    created.push(user_view);
                }
                Err(error) => {
                    failed.push(BulkUserError {
                        email: normalized_email,
                        code: format!("{:?}", error.code).to_ascii_lowercase(),
                        message: error.message.to_string(),
                    });
                    if fail_fast {
                        break;
                    }
                }
            }
        }

        self.append_event(
            "identity.user.bulk_created.v1",
            "user",
            "bulk",
            "bulk_created",
            serde_json::json!({
                "attempted": created.len() + failed.len(),
                "created_count": created.len(),
                "failed_count": failed.len(),
            }),
            context,
        )
        .await?;

        let response = CreateUsersBulkResponse {
            attempted: created.len() + failed.len(),
            created_count: created.len(),
            failed_count: failed.len(),
            created,
            failed,
        };
        let status = if response.failed_count == 0 {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };
        json_response(status, &response)
    }

    async fn create_user_record_locked(
        &self,
        request: CreateUserRequest,
        context: &RequestContext,
    ) -> Result<(UserView, String, u64)> {
        let email = validate_email(&request.email)?;
        let display_name = validate_nonempty_trimmed(request.display_name, "display_name")?;
        let password = validate_nonempty_trimmed(request.password, "password")?;

        self.ensure_email_available(&email).await?;
        let id = UserId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate user id").with_detail(error.to_string())
        })?;
        let etag = sha256_hex(id.as_str().as_bytes());
        let user = UserRecord {
            id: id.clone(),
            email: email.clone(),
            display_name,
            password_hash: hash_user_password(password).await?,
            mfa_enabled: false,
            suspended: false,
            metadata: ResourceMetadata::new(
                OwnershipScope::User,
                Some(id.to_string()),
                etag.clone(),
            ),
        };
        let index_record = UserEmailIndexRecord {
            email: email.clone(),
            user_id: id.clone(),
            created_at: OffsetDateTime::now_utc(),
        };
        let event = Self::build_event(
            "identity.user.created.v1",
            "user",
            id.as_str(),
            "created",
            serde_json::json!({ "email": email }),
            context,
        )?;

        let mut batch = self.write_journal.batch();
        batch.create_metadata(&self.users, id.as_str(), user.clone())?;
        batch.create_metadata(&self.users_by_email, &email, index_record)?;
        self.queue_batched_outbox_event(&mut batch, &event)?;
        batch.commit().await?;
        self.append_audit_event(&event).await?;

        Ok((UserView::from(&user), etag, INITIAL_DOCUMENT_VERSION))
    }

    async fn ensure_email_available(&self, email: &str) -> Result<()> {
        if let Some(index) = self.users_by_email.get(email).await?
            && !index.deleted
        {
            return Err(PlatformError::conflict("email already exists"));
        }
        Ok(())
    }

    async fn create_session(
        &self,
        request: CreateSessionRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let email = validate_email(&request.email)?;
        let password = validate_nonempty_trimmed(request.password, "password")?;
        let user = self
            .find_user_by_email(&email)
            .await?
            .ok_or_else(|| PlatformError::new(ErrorCode::Unauthorized, "invalid credentials"))?;

        if user.suspended {
            return Err(PlatformError::forbidden("user is suspended"));
        }

        if !verify_user_password(password, user.password_hash.clone()).await? {
            return Err(PlatformError::new(
                ErrorCode::Unauthorized,
                "invalid credentials",
            ));
        }

        let session_id = SessionId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate session id")
                .with_detail(error.to_string())
        })?;
        let issued_at = OffsetDateTime::now_utc();
        let session = SessionRecord {
            id: session_id.clone(),
            user_id: user.id.clone(),
            issued_at,
            expires_at: issued_at + Duration::days(1),
            metadata: ResourceMetadata::new(
                OwnershipScope::User,
                Some(user.id.to_string()),
                sha256_hex(session_id.as_str().as_bytes()),
            ),
        };
        self.sessions
            .create(session_id.as_str(), session.clone())
            .await?;
        self.append_event(
            "identity.session.created.v1",
            "session",
            session_id.as_str(),
            "created",
            serde_json::json!({ "user_id": user.id }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &session)
    }

    async fn create_api_key(
        &self,
        request: CreateApiKeyRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let user_id = UserId::parse(request.user_id).map_err(|error| {
            PlatformError::invalid("invalid user_id").with_detail(error.to_string())
        })?;
        let stored_user = self
            .users
            .get(user_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("user does not exist"))?;
        if stored_user.deleted {
            return Err(PlatformError::not_found("user does not exist"));
        }
        let user = stored_user.value;
        if user.suspended {
            return Err(PlatformError::forbidden("user is suspended"));
        }
        let name = validate_nonempty_trimmed(request.name, "name")?;

        let id = ApiKeyId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate api key id")
                .with_detail(error.to_string())
        })?;
        let issued_at = OffsetDateTime::now_utc();
        let secret = base64url_encode(&random_bytes(24)?);
        let preview = secret.chars().take(8).collect::<String>();
        let record = ApiKeyRecord {
            id: id.clone(),
            user_id,
            name,
            secret_version: initial_credential_version(),
            secret_preview: preview,
            secret_hash: sha256_hex(secret.as_bytes()),
            issued_at: Some(issued_at),
            active: true,
            previous_credentials: Vec::new(),
            metadata: ResourceMetadata::new(
                OwnershipScope::User,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let index_record = ApiKeySecretHashIndexRecord {
            secret_hash: record.secret_hash.clone(),
            api_key_id: id.clone(),
            created_at: issued_at,
        };
        let event = Self::build_event(
            "identity.api_key.created.v1",
            "api_key",
            id.as_str(),
            "created",
            serde_json::json!({
                "name": record.name,
                "version": record.secret_version,
            }),
            context,
        )?;

        let mut batch = self.write_journal.batch();
        batch.create_document(&self.api_keys, id.as_str(), record.clone())?;
        batch.create_metadata(
            &self.api_keys_by_secret_hash,
            &record.secret_hash,
            index_record,
        )?;
        self.queue_batched_outbox_event(&mut batch, &event)?;
        batch.commit().await?;
        self.append_audit_event(&event).await?;

        json_response(
            StatusCode::CREATED,
            &api_key_secret_response(&record, &secret),
        )
    }

    async fn rotate_api_key(
        &self,
        api_key_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let api_key_id = ApiKeyId::parse(api_key_id).map_err(|error| {
            PlatformError::invalid("invalid api_key_id").with_detail(error.to_string())
        })?;
        let stored = self
            .api_keys
            .get(api_key_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("api key does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("api key does not exist"));
        }
        let stored_user = self
            .users
            .get(stored.value.user_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("user does not exist"))?;
        if stored_user.deleted {
            return Err(PlatformError::not_found("user does not exist"));
        }
        if stored_user.value.suspended {
            return Err(PlatformError::forbidden("user is suspended"));
        }
        if !stored.value.active || resource_metadata_is_revoked(&stored.value.metadata) {
            return Err(PlatformError::conflict("api key is not active"));
        }

        let secret = base64url_encode(&random_bytes(24)?);
        let issued_at = OffsetDateTime::now_utc();
        let preview = secret.chars().take(8).collect::<String>();
        let secret_hash = sha256_hex(secret.as_bytes());

        let mut record = stored.value.clone();
        let previous_hash = record.secret_hash.clone();
        let previous_version = record.secret_version;
        record
            .previous_credentials
            .push(current_api_key_credential(&record));
        record.secret_version =
            next_credential_version(record.secret_version, "api key secret version")?;
        record.secret_preview = preview;
        record.secret_hash = secret_hash.clone();
        record.issued_at = Some(issued_at);
        record.active = true;
        record.metadata.lifecycle = ResourceLifecycleState::Ready;
        record.metadata.deleted_at = None;
        record.metadata.touch(sha256_hex(
            format!("{}:{}", api_key_id.as_str(), record.secret_version).as_bytes(),
        ));

        let event = Self::build_event(
            "identity.api_key.rotated.v1",
            "api_key",
            api_key_id.as_str(),
            "rotated",
            serde_json::json!({
                "previous_version": previous_version,
                "version": record.secret_version,
            }),
            context,
        )?;

        let mut batch = self.write_journal.batch();
        batch.upsert_document(
            &self.api_keys,
            api_key_id.as_str(),
            record.clone(),
            Some(stored.version),
        )?;
        self.queue_api_key_secret_hash_update(
            &mut batch,
            Some(&previous_hash),
            Some(&secret_hash),
            &api_key_id,
            issued_at,
        )
        .await?;
        self.queue_batched_outbox_event(&mut batch, &event)?;
        batch.commit().await?;
        self.append_audit_event(&event).await?;

        json_response(StatusCode::OK, &api_key_secret_response(&record, &secret))
    }

    async fn revoke_api_key(
        &self,
        api_key_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let api_key_id = ApiKeyId::parse(api_key_id).map_err(|error| {
            PlatformError::invalid("invalid api_key_id").with_detail(error.to_string())
        })?;
        let stored = self
            .api_keys
            .get(api_key_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("api key does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("api key does not exist"));
        }

        let mut record = stored.value.clone();
        if resource_metadata_is_revoked(&record.metadata) {
            return json_response(StatusCode::OK, &api_key_response(&record));
        }

        record.active = false;
        record.metadata.lifecycle = ResourceLifecycleState::Deleted;
        record.metadata.deleted_at = Some(OffsetDateTime::now_utc());
        record.metadata.touch(sha256_hex(
            format!("{}:revoked", api_key_id.as_str()).as_bytes(),
        ));

        let event = Self::build_event(
            "identity.api_key.revoked.v1",
            "api_key",
            api_key_id.as_str(),
            "revoked",
            serde_json::json!({
                "version": record.secret_version,
            }),
            context,
        )?;

        let mut batch = self.write_journal.batch();
        batch.upsert_document(
            &self.api_keys,
            api_key_id.as_str(),
            record.clone(),
            Some(stored.version),
        )?;
        self.queue_api_key_secret_hash_update(
            &mut batch,
            Some(&record.secret_hash),
            None,
            &api_key_id,
            current_api_key_issued_at(&record),
        )
        .await?;
        self.queue_batched_outbox_event(&mut batch, &event)?;
        batch.commit().await?;
        self.append_audit_event(&event).await?;

        json_response(StatusCode::OK, &api_key_response(&record))
    }

    async fn list_workload_identities(&self) -> Result<Vec<WorkloadIdentityView>> {
        Ok(self
            .workload_identities
            .list()
            .await?
            .into_iter()
            .filter(|(_, record)| !record.deleted)
            .map(|(_, record)| WorkloadIdentityView::from(&record.value))
            .collect())
    }

    async fn create_workload_identity(
        &self,
        request: CreateWorkloadIdentityRequest,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let _guard = self.workload_identity_guard.lock().await;
        let (identity, token, etag, version) = self
            .create_workload_identity_record_locked(request, context)
            .await
            .map_err(|error| error.with_correlation_id(context.correlation_id.clone()))?;

        with_etag(
            json_response(
                StatusCode::CREATED,
                &CreateWorkloadIdentityResponse { identity, token },
            )?,
            &etag,
        )
        .map_err(|error| error.with_correlation_id(context.correlation_id.clone()))
        .map(|mut response| {
            response.headers_mut().insert(
                "x-record-version",
                http::HeaderValue::from_str(&version.to_string())
                    .unwrap_or_else(|_| http::HeaderValue::from_static("1")),
            );
            response
        })
    }

    async fn create_workload_identity_record_locked(
        &self,
        request: CreateWorkloadIdentityRequest,
        context: &RequestContext,
    ) -> Result<(WorkloadIdentityView, String, String, u64)> {
        let Some(workload_identity_key) = &self.workload_identity_key else {
            return Err(PlatformError::unavailable(
                "workload identity issuance requires configured sealing key",
            ));
        };

        let subject = normalize_workload_identity_subject(request.subject)?;
        let display_name = validate_nonempty_trimmed(request.display_name, "display_name")?;
        let project_id = parse_optional_project_id(request.project_id)?;
        let workload_id = parse_optional_workload_id(request.workload_id)?;
        let audiences = normalize_workload_identity_audiences(request.audiences)?;
        let ttl_seconds = normalize_workload_identity_ttl_seconds(request.ttl_seconds)?;
        let ttl_seconds = i64::try_from(ttl_seconds).map_err(|_| {
            PlatformError::invalid("ttl_seconds exceeds supported range for local runtime")
        })?;

        self.ensure_workload_subject_available(&subject).await?;

        let id = WorkloadIdentityId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate workload identity id")
                .with_detail(error.to_string())
        })?;
        let etag = sha256_hex(id.as_str().as_bytes());
        let principal = PrincipalIdentity::new(PrincipalKind::Workload, subject.clone())
            .with_credential_id(id.to_string());
        let issued_at = OffsetDateTime::now_utc();
        let token = base64url_encode(&random_bytes(32)?);
        let preview = token.chars().take(10).collect::<String>();
        let (ownership_scope, owner_id) = workload_identity_ownership(project_id.as_ref());
        let mut metadata = ResourceMetadata::new(ownership_scope, owner_id, etag.clone());
        metadata.lifecycle = ResourceLifecycleState::Ready;

        let record = WorkloadIdentityRecord {
            id: id.clone(),
            principal,
            display_name,
            project_id: project_id.clone(),
            workload_id: workload_id.clone(),
            audiences: audiences.clone(),
            active: true,
            credential: WorkloadIdentityCredentialRecord {
                version: 1,
                secret_preview: preview,
                secret_ciphertext: seal_secret(
                    workload_identity_key,
                    &SecretString::new(token.clone()),
                )?,
                secret_hash: sha256_hex(token.as_bytes()),
                issued_at,
                expires_at: issued_at + Duration::seconds(ttl_seconds),
            },
            previous_credentials: Vec::new(),
            metadata,
        };

        let index_record = WorkloadIdentitySubjectIndexRecord {
            subject: subject.clone(),
            workload_identity_id: id.clone(),
            created_at: issued_at,
        };
        let event = Self::build_event(
            "identity.workload_identity.issued.v1",
            "workload_identity",
            id.as_str(),
            "issued",
            serde_json::json!({
                "subject": subject,
                "project_id": project_id.as_ref().map(ToString::to_string),
                "workload_id": workload_id.as_ref().map(ToString::to_string),
                "audiences": audiences,
                "expires_at": record.credential.expires_at,
            }),
            context,
        )?;

        let mut batch = self.write_journal.batch();
        batch.create_document(&self.workload_identities, id.as_str(), record.clone())?;
        batch.create_metadata(&self.workload_identities_by_subject, &subject, index_record)?;
        self.queue_batched_outbox_event(&mut batch, &event)?;
        batch.commit().await?;
        self.append_audit_event(&event).await?;

        Ok((
            WorkloadIdentityView::from(&record),
            token,
            etag,
            INITIAL_DOCUMENT_VERSION,
        ))
    }

    async fn rotate_workload_identity(
        &self,
        workload_identity_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let Some(workload_identity_key) = &self.workload_identity_key else {
            return Err(PlatformError::unavailable(
                "workload identity issuance requires configured sealing key",
            ));
        };
        let workload_identity_id =
            WorkloadIdentityId::parse(workload_identity_id).map_err(|error| {
                PlatformError::invalid("invalid workload_identity_id")
                    .with_detail(error.to_string())
            })?;
        let stored = self
            .workload_identities
            .get(workload_identity_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("workload identity does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("workload identity does not exist"));
        }
        if !stored.value.active || resource_metadata_is_revoked(&stored.value.metadata) {
            return Err(PlatformError::conflict("workload identity is not active"));
        }

        let ttl_seconds = workload_identity_credential_ttl_seconds(&stored.value.credential)?;
        let issued_at = OffsetDateTime::now_utc();
        let token = base64url_encode(&random_bytes(32)?);
        let preview = token.chars().take(10).collect::<String>();
        let secret_hash = sha256_hex(token.as_bytes());

        let mut record = stored.value.clone();
        let previous_version = record.credential.version;
        record.previous_credentials.push(record.credential.clone());
        record.credential = WorkloadIdentityCredentialRecord {
            version: next_credential_version(
                record.credential.version,
                "workload identity credential version",
            )?,
            secret_preview: preview,
            secret_ciphertext: seal_secret(
                workload_identity_key,
                &SecretString::new(token.clone()),
            )?,
            secret_hash,
            issued_at,
            expires_at: issued_at + Duration::seconds(ttl_seconds),
        };
        record.active = true;
        record.metadata.lifecycle = ResourceLifecycleState::Ready;
        record.metadata.deleted_at = None;
        record.metadata.touch(sha256_hex(
            format!(
                "{}:{}",
                workload_identity_id.as_str(),
                record.credential.version
            )
            .as_bytes(),
        ));

        let event = Self::build_event(
            "identity.workload_identity.rotated.v1",
            "workload_identity",
            workload_identity_id.as_str(),
            "rotated",
            serde_json::json!({
                "subject": record.principal.subject,
                "previous_version": previous_version,
                "version": record.credential.version,
                "expires_at": record.credential.expires_at,
            }),
            context,
        )?;

        let mut batch = self.write_journal.batch();
        batch.upsert_document(
            &self.workload_identities,
            workload_identity_id.as_str(),
            record.clone(),
            Some(stored.version),
        )?;
        self.queue_batched_outbox_event(&mut batch, &event)?;
        batch.commit().await?;
        self.append_audit_event(&event).await?;

        json_response(
            StatusCode::OK,
            &CreateWorkloadIdentityResponse {
                identity: WorkloadIdentityView::from(&record),
                token,
            },
        )
    }

    async fn revoke_workload_identity(
        &self,
        workload_identity_id: &str,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let workload_identity_id =
            WorkloadIdentityId::parse(workload_identity_id).map_err(|error| {
                PlatformError::invalid("invalid workload_identity_id")
                    .with_detail(error.to_string())
            })?;
        let stored = self
            .workload_identities
            .get(workload_identity_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("workload identity does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("workload identity does not exist"));
        }

        let mut record = stored.value.clone();
        if resource_metadata_is_revoked(&record.metadata) {
            return json_response(StatusCode::OK, &WorkloadIdentityView::from(&record));
        }

        record.active = false;
        record.metadata.lifecycle = ResourceLifecycleState::Deleted;
        record.metadata.deleted_at = Some(OffsetDateTime::now_utc());
        record.metadata.touch(sha256_hex(
            format!("{}:revoked", workload_identity_id.as_str()).as_bytes(),
        ));

        let event = Self::build_event(
            "identity.workload_identity.revoked.v1",
            "workload_identity",
            workload_identity_id.as_str(),
            "revoked",
            serde_json::json!({
                "subject": record.principal.subject,
                "version": record.credential.version,
            }),
            context,
        )?;

        let mut batch = self.write_journal.batch();
        batch.upsert_document(
            &self.workload_identities,
            workload_identity_id.as_str(),
            record.clone(),
            Some(stored.version),
        )?;
        self.queue_batched_outbox_event(&mut batch, &event)?;
        batch.commit().await?;
        self.append_audit_event(&event).await?;

        json_response(StatusCode::OK, &WorkloadIdentityView::from(&record))
    }

    async fn ensure_workload_subject_available(&self, subject: &str) -> Result<()> {
        if let Some(index) = self.workload_identities_by_subject.get(subject).await?
            && !index.deleted
        {
            return Err(PlatformError::conflict(
                "workload identity subject already exists",
            ));
        }
        Ok(())
    }

    async fn set_suspension(
        &self,
        user_id: &str,
        suspended: bool,
        context: &RequestContext,
    ) -> Result<Response<ApiBody>> {
        let stored = self
            .users
            .get(user_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("user does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("user does not exist"));
        }
        let mut user = stored.value;
        user.suspended = suspended;
        user.metadata.lifecycle = if suspended {
            ResourceLifecycleState::Suspended
        } else {
            ResourceLifecycleState::Ready
        };
        user.metadata.touch(sha256_hex(user.id.as_str().as_bytes()));
        self.users
            .upsert(user_id, user.clone(), Some(stored.version))
            .await?;
        self.append_event(
            if suspended {
                "identity.user.suspended.v1"
            } else {
                "identity.user.reactivated.v1"
            },
            "user",
            user_id,
            if suspended {
                "suspended"
            } else {
                "reactivated"
            },
            serde_json::json!({}),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &UserView::from(&user))
    }

    async fn summarize_identity(&self) -> Result<IdentitySummary> {
        let users = self
            .users
            .list()
            .await?
            .into_iter()
            .filter_map(|(_, record)| (!record.deleted).then_some(record.value))
            .collect::<Vec<_>>();
        let suspended_users = users.iter().filter(|user| user.suspended).count();
        let user_summary = IdentityUserSummary {
            total: users.len(),
            active: users.len().saturating_sub(suspended_users),
            suspended: suspended_users,
        };

        let now = OffsetDateTime::now_utc();
        let sessions = self
            .sessions
            .list()
            .await?
            .into_iter()
            .filter_map(|(_, record)| (!record.deleted).then_some(record.value))
            .collect::<Vec<_>>();
        let active_sessions = sessions
            .iter()
            .filter(|session| session.issued_at <= now && session.expires_at > now)
            .count();
        let session_summary = IdentitySessionSummary {
            total: sessions.len(),
            active: active_sessions,
            expired: sessions.len().saturating_sub(active_sessions),
        };

        let api_keys = self
            .api_keys
            .list()
            .await?
            .into_iter()
            .filter_map(|(_, record)| (!record.deleted).then_some(record.value))
            .collect::<Vec<_>>();
        let active_api_keys = api_keys.iter().filter(|api_key| api_key.active).count();
        let api_key_summary = IdentityApiKeySummary {
            total: api_keys.len(),
            active: active_api_keys,
            inactive: api_keys.len().saturating_sub(active_api_keys),
        };

        let identities = self
            .workload_identities
            .list()
            .await?
            .into_iter()
            .filter_map(|(_, record)| (!record.deleted).then_some(record.value))
            .collect::<Vec<_>>();
        let active_identities = identities.iter().filter(|identity| identity.active).count();
        let mut by_project = BTreeMap::<String, ProjectWorkloadIdentitySummary>::new();
        let mut unscoped = 0_usize;
        for identity in &identities {
            if let Some(project_id) = identity.project_id.as_ref() {
                let entry = by_project.entry(project_id.to_string()).or_insert_with(|| {
                    ProjectWorkloadIdentitySummary {
                        project_id: project_id.to_string(),
                        total: 0,
                        active: 0,
                        inactive: 0,
                    }
                });
                entry.total = entry.total.saturating_add(1);
                if identity.active {
                    entry.active = entry.active.saturating_add(1);
                } else {
                    entry.inactive = entry.inactive.saturating_add(1);
                }
            } else {
                unscoped = unscoped.saturating_add(1);
            }
        }
        let workload_identity_summary = IdentityWorkloadIdentitySummary {
            total: identities.len(),
            active: active_identities,
            inactive: identities.len().saturating_sub(active_identities),
            unscoped,
            by_project: by_project.into_values().collect(),
        };
        let credential_lifecycle = self.credential_lifecycle_report().await?.summary;

        Ok(IdentitySummary {
            users: user_summary,
            sessions: session_summary,
            api_keys: api_key_summary,
            workload_identities: workload_identity_summary,
            credential_lifecycle,
        })
    }

    async fn credential_lifecycle_report(&self) -> Result<IdentityCredentialLifecycleReport> {
        let generated_at = OffsetDateTime::now_utc();
        let users_by_id = self
            .users
            .list()
            .await?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let mut entries = Vec::new();

        for (session_id, stored) in self.sessions.list().await? {
            let owner = users_by_id.get(stored.value.user_id.as_str());
            let state = if stored.deleted
                || resource_metadata_is_revoked(&stored.value.metadata)
                || user_owner_is_revoked(owner)
            {
                IdentityCredentialLifecycleState::Revoked
            } else if user_owner_is_suspended(owner) {
                IdentityCredentialLifecycleState::SuspendedOwner
            } else {
                credential_window_state(
                    stored.value.issued_at,
                    stored.value.expires_at,
                    generated_at,
                )
            };
            entries.push(IdentityCredentialLifecycleEntry {
                kind: IdentityCredentialLifecycleKind::Session,
                id: session_id,
                state,
                ownership_scope: stored.value.metadata.ownership_scope.clone(),
                owner_id: Some(stored.value.user_id.to_string()),
                issued_at: stored.value.issued_at,
                expires_at: Some(stored.value.expires_at),
                principal_subject: Some(user_principal_subject(&stored.value.user_id)),
                source_kind: None,
                source_id: None,
                version: None,
                secret_preview: None,
            });
        }

        for (api_key_id, stored) in self.api_keys.list().await? {
            let owner = users_by_id.get(stored.value.user_id.as_str());
            let state = if stored.deleted
                || resource_metadata_is_revoked(&stored.value.metadata)
                || user_owner_is_revoked(owner)
            {
                IdentityCredentialLifecycleState::Revoked
            } else if user_owner_is_suspended(owner) {
                IdentityCredentialLifecycleState::SuspendedOwner
            } else if !stored.value.active {
                IdentityCredentialLifecycleState::Inactive
            } else {
                IdentityCredentialLifecycleState::Active
            };
            let owner_id = Some(stored.value.user_id.to_string());
            let principal_subject = Some(user_principal_subject(&stored.value.user_id));
            let issued_at = current_api_key_issued_at(&stored.value);
            entries.push(IdentityCredentialLifecycleEntry {
                kind: IdentityCredentialLifecycleKind::ApiKey,
                id: api_key_id.clone(),
                state,
                ownership_scope: stored.value.metadata.ownership_scope.clone(),
                owner_id: owner_id.clone(),
                issued_at,
                expires_at: None,
                principal_subject: principal_subject.clone(),
                source_kind: None,
                source_id: None,
                version: None,
                secret_preview: None,
            });
            for credential in &stored.value.previous_credentials {
                entries.push(IdentityCredentialLifecycleEntry {
                    kind: IdentityCredentialLifecycleKind::SecretVersion,
                    id: secret_version_entry_id(
                        IdentityCredentialSecretSourceKind::ApiKey,
                        &api_key_id,
                        credential.version,
                    ),
                    state: IdentityCredentialLifecycleState::Revoked,
                    ownership_scope: stored.value.metadata.ownership_scope.clone(),
                    owner_id: owner_id.clone(),
                    issued_at: credential.issued_at,
                    expires_at: None,
                    principal_subject: principal_subject.clone(),
                    source_kind: Some(IdentityCredentialSecretSourceKind::ApiKey),
                    source_id: Some(api_key_id.clone()),
                    version: Some(credential.version),
                    secret_preview: Some(credential.secret_preview.clone()),
                });
            }
            entries.push(IdentityCredentialLifecycleEntry {
                kind: IdentityCredentialLifecycleKind::SecretVersion,
                id: secret_version_entry_id(
                    IdentityCredentialSecretSourceKind::ApiKey,
                    &api_key_id,
                    stored.value.secret_version,
                ),
                state,
                ownership_scope: stored.value.metadata.ownership_scope.clone(),
                owner_id,
                issued_at,
                expires_at: None,
                principal_subject,
                source_kind: Some(IdentityCredentialSecretSourceKind::ApiKey),
                source_id: Some(api_key_id),
                version: Some(stored.value.secret_version),
                secret_preview: Some(stored.value.secret_preview.clone()),
            });
        }

        for (identity_id, stored) in self.workload_identities.list().await? {
            let state = if stored.deleted || resource_metadata_is_revoked(&stored.value.metadata) {
                IdentityCredentialLifecycleState::Revoked
            } else if !stored.value.active {
                IdentityCredentialLifecycleState::Inactive
            } else {
                credential_window_state(
                    stored.value.credential.issued_at,
                    stored.value.credential.expires_at,
                    generated_at,
                )
            };
            let owner_id = stored.value.metadata.owner_id.clone();
            let issued_at = stored.value.credential.issued_at;
            let expires_at = Some(stored.value.credential.expires_at);
            let principal_subject = Some(stored.value.principal.subject.clone());
            entries.push(IdentityCredentialLifecycleEntry {
                kind: IdentityCredentialLifecycleKind::WorkloadToken,
                id: identity_id.clone(),
                state,
                ownership_scope: stored.value.metadata.ownership_scope.clone(),
                owner_id: owner_id.clone(),
                issued_at,
                expires_at,
                principal_subject: principal_subject.clone(),
                source_kind: None,
                source_id: None,
                version: None,
                secret_preview: None,
            });
            for credential in &stored.value.previous_credentials {
                entries.push(IdentityCredentialLifecycleEntry {
                    kind: IdentityCredentialLifecycleKind::SecretVersion,
                    id: secret_version_entry_id(
                        IdentityCredentialSecretSourceKind::WorkloadToken,
                        &identity_id,
                        credential.version,
                    ),
                    state: IdentityCredentialLifecycleState::Revoked,
                    ownership_scope: stored.value.metadata.ownership_scope.clone(),
                    owner_id: owner_id.clone(),
                    issued_at: credential.issued_at,
                    expires_at: Some(credential.expires_at),
                    principal_subject: principal_subject.clone(),
                    source_kind: Some(IdentityCredentialSecretSourceKind::WorkloadToken),
                    source_id: Some(identity_id.clone()),
                    version: Some(credential.version),
                    secret_preview: Some(credential.secret_preview.clone()),
                });
            }
            entries.push(IdentityCredentialLifecycleEntry {
                kind: IdentityCredentialLifecycleKind::SecretVersion,
                id: secret_version_entry_id(
                    IdentityCredentialSecretSourceKind::WorkloadToken,
                    &identity_id,
                    stored.value.credential.version,
                ),
                state,
                ownership_scope: stored.value.metadata.ownership_scope.clone(),
                owner_id,
                issued_at,
                expires_at,
                principal_subject,
                source_kind: Some(IdentityCredentialSecretSourceKind::WorkloadToken),
                source_id: Some(identity_id),
                version: Some(stored.value.credential.version),
                secret_preview: Some(stored.value.credential.secret_preview.clone()),
            });
        }

        entries.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.issued_at.cmp(&right.issued_at))
                .then_with(|| left.id.cmp(&right.id))
        });

        Ok(IdentityCredentialLifecycleReport {
            generated_at,
            summary: Self::summarize_credential_lifecycle_entries(&entries),
            entries,
        })
    }

    fn summarize_credential_lifecycle_entries(
        entries: &[IdentityCredentialLifecycleEntry],
    ) -> IdentityCredentialLifecycleSummary {
        let mut by_kind = BTreeMap::<IdentityCredentialLifecycleKind, usize>::new();
        let mut by_state = BTreeMap::<IdentityCredentialLifecycleState, usize>::new();

        for entry in entries {
            by_kind
                .entry(entry.kind)
                .and_modify(|total| *total = total.saturating_add(1))
                .or_insert(1);
            by_state
                .entry(entry.state)
                .and_modify(|total| *total = total.saturating_add(1))
                .or_insert(1);
        }

        IdentityCredentialLifecycleSummary {
            total: entries.len(),
            by_kind: by_kind
                .into_iter()
                .map(|(kind, total)| IdentityCredentialLifecycleKindSummary { kind, total })
                .collect(),
            by_state: by_state
                .into_iter()
                .map(|(state, total)| IdentityCredentialLifecycleStateSummary { state, total })
                .collect(),
        }
    }

    fn build_event(
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
        details: serde_json::Value,
        context: &RequestContext,
    ) -> Result<PlatformEvent> {
        let actor_subject = context
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
        Ok(PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("identity"),
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
        })
    }

    fn build_relay_publish_request(event: PlatformEvent) -> RelayPublishRequest<PlatformEvent> {
        let event_type = event.header.event_type.clone();
        let idempotency = event.header.event_id.to_string();
        RelayPublishRequest::new("identity.events.v1", event)
            .with_idempotency_key(idempotency)
            .with_source_service("identity")
            .with_event_type(event_type)
    }

    fn queue_batched_outbox_event(
        &self,
        batch: &mut MetadataWriteBatch,
        event: &PlatformEvent,
    ) -> Result<()> {
        let envelope = DurableEventRelay::<PlatformEvent>::build_publish_envelope(
            Self::build_relay_publish_request(event.clone()),
        )?;
        let envelope_id = envelope.id.clone();
        let outbox_store = self.outbox.local_document_store();
        batch.create_document(&outbox_store, &envelope_id, envelope)
    }

    async fn append_audit_event(&self, event: &PlatformEvent) -> Result<()> {
        self.audit_log.append(event).await?;
        Ok(())
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
        let event = Self::build_event(
            event_type,
            resource_kind,
            resource_id,
            action,
            details,
            context,
        )?;
        self.append_audit_event(&event).await?;
        self.outbox
            .publish(Self::build_relay_publish_request(event))
            .await?;
        Ok(())
    }
}

impl HttpService for IdentityService {
    fn name(&self) -> &'static str {
        "identity"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/identity")];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        context: RequestContext,
    ) -> uhost_runtime::ResponseFuture<'a> {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let segments = path_segments(&path);

            if identity_endpoint_requires_operator_principal(&method, segments.as_slice()) {
                require_operator_or_local_dev(&context, "identity administration")?;
            }

            match (method, segments.as_slice()) {
                (Method::GET, ["identity"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["identity", "summary"]) => {
                    let summary = self.summarize_identity().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["identity", "credential-lifecycle"]) => {
                    let report = self.credential_lifecycle_report().await?;
                    json_response(StatusCode::OK, &report).map(Some)
                }
                (Method::GET, ["identity", "users"]) => {
                    let users = self
                        .users
                        .list()
                        .await?
                        .into_iter()
                        .filter(|(_, record)| !record.deleted)
                        .map(|(_, record)| UserView::from(&record.value))
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &users).map(Some)
                }
                (Method::POST, ["identity", "users"]) => {
                    let body: CreateUserRequest = parse_json(request).await?;
                    self.create_user(body, &context).await.map(Some)
                }
                (Method::POST, ["identity", "users", "bulk"]) => {
                    let body: CreateUsersBulkRequest = parse_json(request).await?;
                    self.create_users_bulk(body, &context).await.map(Some)
                }
                (Method::GET, ["identity", "users", user_id]) => {
                    let user_id = UserId::parse(*user_id).map_err(|error| {
                        PlatformError::invalid("invalid user_id").with_detail(error.to_string())
                    })?;
                    let user = self
                        .users
                        .get(user_id.as_str())
                        .await?
                        .ok_or_else(|| PlatformError::not_found("user does not exist"))?;
                    if user.deleted {
                        return Err(PlatformError::not_found("user does not exist"));
                    }
                    json_response(StatusCode::OK, &UserView::from(&user.value)).map(Some)
                }
                (Method::POST, ["identity", "users", user_id, "suspend"]) => {
                    let user_id = UserId::parse(*user_id).map_err(|error| {
                        PlatformError::invalid("invalid user_id").with_detail(error.to_string())
                    })?;
                    self.set_suspension(user_id.as_str(), true, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["identity", "users", user_id, "reactivate"]) => {
                    let user_id = UserId::parse(*user_id).map_err(|error| {
                        PlatformError::invalid("invalid user_id").with_detail(error.to_string())
                    })?;
                    self.set_suspension(user_id.as_str(), false, &context)
                        .await
                        .map(Some)
                }
                (Method::POST, ["identity", "sessions"]) => {
                    let body: CreateSessionRequest = parse_json(request).await?;
                    self.create_session(body, &context).await.map(Some)
                }
                (Method::POST, ["identity", "api-keys"]) => {
                    let body: CreateApiKeyRequest = parse_json(request).await?;
                    self.create_api_key(body, &context).await.map(Some)
                }
                (Method::POST, ["identity", "api-keys", api_key_id, "rotate"]) => {
                    self.rotate_api_key(api_key_id, &context).await.map(Some)
                }
                (Method::POST, ["identity", "api-keys", api_key_id, "revoke"]) => {
                    self.revoke_api_key(api_key_id, &context).await.map(Some)
                }
                (Method::GET, ["identity", "workload-identities"]) => {
                    json_response(StatusCode::OK, &self.list_workload_identities().await?).map(Some)
                }
                (Method::POST, ["identity", "workload-identities"]) => {
                    let body: CreateWorkloadIdentityRequest = parse_json(request).await?;
                    self.create_workload_identity(body, &context)
                        .await
                        .map(Some)
                }
                (
                    Method::POST,
                    [
                        "identity",
                        "workload-identities",
                        workload_identity_id,
                        "rotate",
                    ],
                ) => self
                    .rotate_workload_identity(workload_identity_id, &context)
                    .await
                    .map(Some),
                (
                    Method::POST,
                    [
                        "identity",
                        "workload-identities",
                        workload_identity_id,
                        "revoke",
                    ],
                ) => self
                    .revoke_workload_identity(workload_identity_id, &context)
                    .await
                    .map(Some),
                (Method::GET, ["identity", "outbox"]) => {
                    let messages = self.outbox.list_all_outbox_messages().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                (Method::DELETE, ["identity", "sessions", session_id]) => {
                    let session_id = SessionId::parse(*session_id).map_err(|error| {
                        PlatformError::invalid("invalid session_id").with_detail(error.to_string())
                    })?;
                    self.sessions.soft_delete(session_id.as_str(), None).await?;
                    empty_response(StatusCode::NO_CONTENT).map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn identity_endpoint_requires_operator_principal(method: &Method, segments: &[&str]) -> bool {
    !matches!(
        (method, segments),
        (&Method::GET, ["identity"]) | (&Method::POST, ["identity", "sessions"])
    )
}

fn require_operator_or_local_dev(context: &RequestContext, capability: &str) -> Result<()> {
    if let Some(principal) = context.principal.as_ref()
        && principal.kind != PrincipalKind::Operator
    {
        return Err(PlatformError::forbidden(format!(
            "{capability} requires an operator principal"
        ))
        .with_correlation_id(context.correlation_id.clone()));
    }
    Ok(())
}

impl BearerTokenAuthorizer for IdentityService {
    fn authorize<'a>(
        &'a self,
        bearer_token: &'a str,
        service_name: &'a str,
    ) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            self.authorize_bearer_token_for_service(bearer_token, service_name)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use http::{Method, Request};
    use http_body_util::{BodyExt, Either, Full};
    use hyper::body::Incoming;
    use serde_json::Value;
    use tempfile::tempdir;
    use time::{Duration, OffsetDateTime};

    use super::{
        CreateApiKeyRequest, CreateSessionRequest, CreateUserRequest, CreateUsersBulkRequest,
        CreateWorkloadIdentityRequest, CreateWorkloadIdentityResponse,
        IdentityCredentialLifecycleKind, IdentityCredentialLifecycleReport,
        IdentityCredentialLifecycleState, IdentityCredentialSecretSourceKind, IdentityService,
        UserEmailIndexRecord, WorkloadIdentitySubjectIndexRecord,
    };
    use uhost_core::{
        ErrorCode, PrincipalIdentity, PrincipalKind, RequestContext, SecretBytes, sha256_hex,
        unseal_secret,
    };
    use uhost_runtime::HttpService;
    use uhost_store::DeliveryState;
    use uhost_types::{OwnershipScope, ProjectId, UserId, WorkloadId, WorkloadIdentityId};

    fn workload_identity_key() -> SecretBytes {
        SecretBytes::new(vec![0x24_u8; 32])
    }

    fn operator_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(
                PrincipalKind::Operator,
                "bootstrap_admin",
            ))
    }

    async fn response_json<T: serde::de::DeserializeOwned>(
        response: http::Response<uhost_api::ApiBody>,
    ) -> T {
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    #[tokio::test]
    async fn create_user_persists_record() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("alice@example.com"),
                    display_name: String::from("Alice"),
                    password: String::from("correct horse battery staple"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);

        let users = service
            .users
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(users.len(), 1);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].source_service.as_deref(), Some("identity"));
        assert_eq!(
            outbox[0].event_type.as_deref(),
            Some("identity.user.created.v1")
        );
        assert_eq!(outbox[0].relay.backend, "local_file");
        assert_eq!(outbox[0].relay.attempts, 0);
        assert_eq!(outbox[0].relay.replay_count, 0);
        assert!(matches!(outbox[0].state, DeliveryState::Pending));
    }

    #[tokio::test]
    async fn created_user_event_supports_replayable_relay_state() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_user(
                CreateUserRequest {
                    email: String::from("replay@example.com"),
                    display_name: String::from("Replay User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let message = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing event relay envelope"));

        let failed = service
            .outbox
            .mark_failed(
                &message.id,
                "dispatcher unavailable",
                OffsetDateTime::now_utc() - Duration::seconds(1),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(failed.state, DeliveryState::Failed { .. }));
        assert_eq!(failed.relay.attempts, 1);

        let replayed = service
            .outbox
            .replay(&message.id, "operator replay")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(matches!(replayed.state, DeliveryState::Pending));
        assert_eq!(replayed.relay.replay_count, 1);

        let ready = service
            .outbox
            .list_ready(10)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(ready.len(), 1);
        assert_eq!(
            ready[0].event_type.as_deref(),
            Some("identity.user.created.v1")
        );
        assert_eq!(ready[0].source_service.as_deref(), Some("identity"));
    }

    #[tokio::test]
    async fn create_user_trims_display_name_and_rejects_blank_password() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("trim@example.com"),
                    display_name: String::from("  Trimmed User  "),
                    password: String::from("correct horse battery staple"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);
        let users = service
            .users
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(users[0].1.value.display_name, "Trimmed User");

        let error = service
            .create_user(
                CreateUserRequest {
                    email: String::from("blank-password@example.com"),
                    display_name: String::from("Blank Password"),
                    password: String::from("   "),
                },
                &context,
            )
            .await
            .expect_err("blank password should be rejected");
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn bulk_create_users_creates_valid_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .create_users_bulk(
                CreateUsersBulkRequest {
                    users: vec![
                        CreateUserRequest {
                            email: String::from("bulk-a@example.com"),
                            display_name: String::from("Bulk A"),
                            password: String::from("pw-a"),
                        },
                        CreateUserRequest {
                            email: String::from("bulk-b@example.com"),
                            display_name: String::from("Bulk B"),
                            password: String::from("pw-b"),
                        },
                    ],
                    fail_fast: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(payload["created_count"].as_u64().unwrap_or_default(), 2);
        assert_eq!(payload["failed_count"].as_u64().unwrap_or_default(), 0);
    }

    #[tokio::test]
    async fn bulk_create_users_reports_duplicate_email_in_payload() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .create_users_bulk(
                CreateUsersBulkRequest {
                    users: vec![
                        CreateUserRequest {
                            email: String::from("dup@example.com"),
                            display_name: String::from("A"),
                            password: String::from("pw-a"),
                        },
                        CreateUserRequest {
                            email: String::from("dup@example.com"),
                            display_name: String::from("B"),
                            password: String::from("pw-b"),
                        },
                    ],
                    fail_fast: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(payload["created_count"].as_u64().unwrap_or_default(), 1);
        assert_eq!(payload["failed_count"].as_u64().unwrap_or_default(), 1);
    }

    #[tokio::test]
    async fn create_session_repairs_stale_email_index() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_user(
                CreateUserRequest {
                    email: String::from("session@example.com"),
                    display_name: String::from("Session User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .users_by_email
            .soft_delete("session@example.com", None)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_session(
                CreateSessionRequest {
                    email: String::from("session@example.com"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);

        let index = service
            .users_by_email
            .get("session@example.com")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .expect("email index should exist after repair");
        assert!(!index.deleted);
    }

    #[tokio::test]
    async fn create_api_key_rejects_suspended_users_and_blank_names() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let user_response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("apikey@example.com"),
                    display_name: String::from("API Key User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let user_body = user_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let user_payload: Value =
            serde_json::from_slice(&user_body).unwrap_or_else(|error| panic!("{error}"));
        let user_id = user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing user id"))
            .to_owned();

        let blank_name_error = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id: user_id.clone(),
                    name: String::from("   "),
                },
                &context,
            )
            .await
            .expect_err("blank API key names should be rejected");
        assert_eq!(blank_name_error.code, uhost_core::ErrorCode::InvalidInput);

        service
            .set_suspension(&user_id, true, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let suspended_error = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id: user_id.clone(),
                    name: String::from("service token"),
                },
                &context,
            )
            .await
            .expect_err("suspended users should not receive API keys");
        assert_eq!(suspended_error.code, uhost_core::ErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn create_api_key_persists_hash_index_and_outbox_event() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let user_response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("apikey-event@example.com"),
                    display_name: String::from("API Key Event User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let user_body = user_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let user_payload: Value =
            serde_json::from_slice(&user_body).unwrap_or_else(|error| panic!("{error}"));
        let user_id = user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing user id"))
            .to_owned();

        let response = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id,
                    name: String::from("automation"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        let secret = payload["secret"]
            .as_str()
            .unwrap_or_else(|| panic!("missing api key secret"));
        let secret_hash = sha256_hex(secret.as_bytes());

        let stored_index = service
            .api_keys_by_secret_hash
            .get(&secret_hash)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing api key hash index"));
        assert!(!stored_index.deleted);

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(outbox.iter().any(|message| {
            message.event_type.as_deref() == Some("identity.api_key.created.v1")
        }));
    }

    #[tokio::test]
    async fn authorize_bearer_token_admits_active_api_keys_as_user_principals() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let user_response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("human@example.com"),
                    display_name: String::from("Human Operator"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let user_body = user_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let user_payload: Value =
            serde_json::from_slice(&user_body).unwrap_or_else(|error| panic!("{error}"));
        let user_id = user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing user id"))
            .to_owned();

        let api_key_response = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id: user_id.clone(),
                    name: String::from("human cli key"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let api_key_body = api_key_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let api_key_payload: Value =
            serde_json::from_slice(&api_key_body).unwrap_or_else(|error| panic!("{error}"));
        let api_key_id = api_key_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing api key id"))
            .to_owned();
        let secret = api_key_payload["secret"]
            .as_str()
            .unwrap_or_else(|| panic!("missing api key secret"))
            .to_owned();
        let secret_hash = sha256_hex(secret.as_bytes());

        let stored_index = service
            .api_keys_by_secret_hash
            .get(&secret_hash)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing api key hash index"));
        service
            .api_keys_by_secret_hash
            .soft_delete(&secret_hash, Some(stored_index.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let principal = service
            .authorize_bearer_token_for_service(&secret, "governance")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("active api key should be admitted"));
        assert_eq!(principal.kind, PrincipalKind::User);
        assert_eq!(principal.subject, format!("user:{user_id}"));
        assert_eq!(
            principal.credential_id.as_deref(),
            Some(api_key_id.as_str())
        );

        let repaired_index = service
            .api_keys_by_secret_hash
            .get(&secret_hash)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing repaired api key hash index"));
        assert!(!repaired_index.deleted);
        assert_eq!(repaired_index.value.api_key_id.as_str(), api_key_id);

        service
            .set_suspension(&user_id, true, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            service
                .authorize_bearer_token_for_service(&secret, "governance")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
    }

    #[tokio::test]
    async fn issue_workload_identity_persists_sealed_credential_and_principal_metadata() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let key = workload_identity_key();
        let service = IdentityService::open_with_master_key(temp.path(), key.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_actor("operator");
        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let workload_id = WorkloadId::generate().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("  svc:Build-Runner  "),
                    display_name: String::from("  Build Runner  "),
                    project_id: Some(project_id.to_string()),
                    workload_id: Some(workload_id.to_string()),
                    audiences: vec![
                        String::from("secrets"),
                        String::from("IDENTITY"),
                        String::from("secrets"),
                    ],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("x-record-version")
                .and_then(|value| value.to_str().ok()),
            Some("1")
        );
        assert!(response.headers().contains_key(http::header::ETAG));

        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        let token = payload["token"]
            .as_str()
            .unwrap_or_else(|| panic!("missing issued token"));
        assert_eq!(payload["identity"]["principal"]["kind"], "workload");
        assert_eq!(
            payload["identity"]["principal"]["subject"],
            "svc:build-runner"
        );
        assert_eq!(payload["identity"]["display_name"], "Build Runner");
        assert_eq!(payload["identity"]["project_id"], project_id.to_string());
        assert_eq!(payload["identity"]["workload_id"], workload_id.to_string());
        assert_eq!(
            payload["identity"]["audiences"],
            serde_json::json!(["secrets", "identity"])
        );

        let stored = service
            .workload_identities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(stored.len(), 1);
        let record = &stored[0].1.value;
        assert_eq!(record.principal.subject, "svc:build-runner");
        assert_eq!(record.display_name, "Build Runner");
        assert_eq!(record.metadata.ownership_scope, OwnershipScope::Project);
        assert_eq!(record.credential.secret_hash, sha256_hex(token.as_bytes()));
        assert_ne!(record.credential.secret_ciphertext, token);
        assert_eq!(
            unseal_secret(&key, &record.credential.secret_ciphertext)
                .unwrap_or_else(|error| panic!("{error}"))
                .expose(),
            token
        );

        let reopened = IdentityService::open_with_master_key(temp.path(), key)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let subject_index = reopened
            .workload_identities_by_subject
            .get("svc:build-runner")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .expect("subject index should persist");
        assert!(!subject_index.deleted);
        assert_eq!(subject_index.value.workload_identity_id, record.id);

        let outbox = reopened
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(outbox.iter().any(|message| {
            message.event_type.as_deref() == Some("identity.workload_identity.issued.v1")
        }));
    }

    #[tokio::test]
    async fn issue_workload_identity_enforces_subject_uniqueness_and_ttl_bounds() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open_with_master_key(temp.path(), workload_identity_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let invalid_subject = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("user:builder"),
                    display_name: String::from("Invalid Subject"),
                    project_id: None,
                    workload_id: None,
                    audiences: Vec::new(),
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .expect_err("invalid subject prefixes must be rejected");
        assert_eq!(invalid_subject.code, uhost_core::ErrorCode::InvalidInput);

        let invalid_ttl = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:builder"),
                    display_name: String::from("Builder"),
                    project_id: None,
                    workload_id: None,
                    audiences: Vec::new(),
                    ttl_seconds: Some(0),
                },
                &context,
            )
            .await
            .expect_err("zero ttl must be rejected");
        assert_eq!(invalid_ttl.code, uhost_core::ErrorCode::InvalidInput);

        service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:builder"),
                    display_name: String::from("Builder"),
                    project_id: None,
                    workload_id: None,
                    audiences: vec![String::from("secrets")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let duplicate = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("  SVC:Builder  "),
                    display_name: String::from("Builder Duplicate"),
                    project_id: None,
                    workload_id: None,
                    audiences: Vec::new(),
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .expect_err("normalized duplicate subjects must conflict");
        assert_eq!(duplicate.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn create_user_batch_conflict_leaves_no_partial_primary_or_outbox() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let existing_user_id = UserId::generate().unwrap_or_else(|error| panic!("{error}"));

        let stale_index = service
            .users_by_email
            .create(
                "batched-conflict@example.com",
                UserEmailIndexRecord {
                    email: String::from("batched-conflict@example.com"),
                    user_id: existing_user_id,
                    created_at: OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .users_by_email
            .soft_delete("batched-conflict@example.com", Some(stale_index.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_user(
                CreateUserRequest {
                    email: String::from("batched-conflict@example.com"),
                    display_name: String::from("Conflict User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .expect_err("stale deleted email index should fail the batch");
        assert_eq!(error.code, ErrorCode::Conflict);

        let users = service
            .users
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(users.is_empty());

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(outbox.is_empty());
    }

    #[tokio::test]
    async fn create_workload_identity_batch_conflict_leaves_no_partial_primary_or_outbox() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open_with_master_key(temp.path(), workload_identity_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let existing_identity_id =
            WorkloadIdentityId::generate().unwrap_or_else(|error| panic!("{error}"));

        let stale_index = service
            .workload_identities_by_subject
            .create(
                "svc:batched-conflict",
                WorkloadIdentitySubjectIndexRecord {
                    subject: String::from("svc:batched-conflict"),
                    workload_identity_id: existing_identity_id,
                    created_at: OffsetDateTime::now_utc(),
                },
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .workload_identities_by_subject
            .soft_delete("svc:batched-conflict", Some(stale_index.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:batched-conflict"),
                    display_name: String::from("Conflict Identity"),
                    project_id: None,
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .expect_err("stale deleted subject index should fail the batch");
        assert_eq!(error.code, ErrorCode::Conflict);

        let identities = service
            .workload_identities
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(identities.is_empty());

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(outbox.is_empty());
    }

    #[tokio::test]
    async fn workload_token_verifier_enforces_runtime_admission_invariants() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open_with_master_key(temp.path(), workload_identity_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:runtime-agent"),
                    display_name: String::from("Runtime Agent"),
                    project_id: None,
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error}"));
        let token = payload["token"]
            .as_str()
            .unwrap_or_else(|| panic!("missing workload token"))
            .to_owned();
        let identity_id = payload["identity"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing workload identity id"))
            .to_owned();

        let principal = service
            .authorize_bearer_token_for_service(&token, "identity")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("valid workload token should be admitted"));
        assert_eq!(principal.kind, PrincipalKind::Workload);
        assert_eq!(principal.subject, "svc:runtime-agent");
        assert_eq!(
            principal.credential_id.as_deref(),
            Some(identity_id.as_str())
        );

        assert!(
            service
                .authorize_bearer_token_for_service("malformed-token", "identity")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        assert!(
            service
                .authorize_bearer_token_for_service(&token, "secrets")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let stored = service
            .workload_identities
            .get(&identity_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored workload identity"));
        let mut inactive = stored.value.clone();
        inactive.active = false;
        service
            .workload_identities
            .upsert(&identity_id, inactive, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            service
                .authorize_bearer_token_for_service(&token, "identity")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let stored = service
            .workload_identities
            .get(&identity_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored workload identity after inactive update"));
        let mut expired = stored.value.clone();
        expired.active = true;
        expired.credential.expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
        service
            .workload_identities
            .upsert(&identity_id, expired, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            service
                .authorize_bearer_token_for_service(&token, "identity")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
    }

    #[tokio::test]
    async fn workload_identity_issuance_preserves_existing_user_session_flow() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open_with_master_key(temp.path(), workload_identity_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("workload:batch-runner"),
                    display_name: String::from("Batch Runner"),
                    project_id: None,
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .create_user(
                CreateUserRequest {
                    email: String::from("compat@example.com"),
                    display_name: String::from("Compat User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_session(
                CreateSessionRequest {
                    email: String::from("compat@example.com"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), http::StatusCode::CREATED);
    }

    #[tokio::test]
    async fn identity_summary_reports_counts_and_project_breakdowns() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let key = workload_identity_key();
        let service = IdentityService::open_with_master_key(temp.path(), key)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let first_user = service
            .create_user(
                CreateUserRequest {
                    email: String::from("summary-a@example.com"),
                    display_name: String::from("Summary A"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_user_body = first_user
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_user_payload: Value =
            serde_json::from_slice(&first_user_body).unwrap_or_else(|error| panic!("{error}"));
        let first_user_id = first_user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing first user id"))
            .to_owned();

        let second_user = service
            .create_user(
                CreateUserRequest {
                    email: String::from("summary-b@example.com"),
                    display_name: String::from("Summary B"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second_user_body = second_user
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let second_user_payload: Value =
            serde_json::from_slice(&second_user_body).unwrap_or_else(|error| panic!("{error}"));
        let second_user_id = second_user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing second user id"))
            .to_owned();

        let _ = service
            .create_session(
                CreateSessionRequest {
                    email: String::from("summary-a@example.com"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_session(
                CreateSessionRequest {
                    email: String::from("summary-b@example.com"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let session_record = service
            .sessions
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|(_, record)| record.value.user_id.as_str() == second_user_id)
            .unwrap_or_else(|| panic!("missing second user session"));
        let mut expired_session = session_record.1.value.clone();
        expired_session.expires_at = OffsetDateTime::now_utc() - Duration::seconds(30);
        service
            .sessions
            .upsert(
                &session_record.0,
                expired_session,
                Some(session_record.1.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_key_response = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id: first_user_id.clone(),
                    name: String::from("summary key a"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_key_body = first_key_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let first_key_payload: Value =
            serde_json::from_slice(&first_key_body).unwrap_or_else(|error| panic!("{error}"));
        let first_key_id = first_key_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing first key id"))
            .to_owned();

        let _ = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id: second_user_id.clone(),
                    name: String::from("summary key b"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let first_key_stored = service
            .api_keys
            .get(&first_key_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing first api key"));
        let mut inactive_key = first_key_stored.value.clone();
        inactive_key.active = false;
        service
            .api_keys
            .upsert(
                first_key_stored.value.id.as_str(),
                inactive_key,
                Some(first_key_stored.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .set_suspension(&second_user_id, true, &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project_id = ProjectId::generate().unwrap_or_else(|error| panic!("{error}"));
        let _ = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:summary-project-a"),
                    display_name: String::from("Project Identity A"),
                    project_id: Some(project_id.to_string()),
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let project_identity_response = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:summary-project-b"),
                    display_name: String::from("Project Identity B"),
                    project_id: Some(project_id.to_string()),
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let project_identity_body = project_identity_response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let project_identity_payload: Value = serde_json::from_slice(&project_identity_body)
            .unwrap_or_else(|error| panic!("{error}"));
        let project_identity_id = project_identity_payload["identity"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing project identity id"))
            .to_owned();

        let _ = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:summary-unscoped"),
                    display_name: String::from("Unscoped Identity"),
                    project_id: None,
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_project_identity = service
            .workload_identities
            .get(&project_identity_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing project identity record"));
        let mut inactive_identity = stored_project_identity.value.clone();
        inactive_identity.active = false;
        let inactive_identity_id = inactive_identity.id.to_string();
        service
            .workload_identities
            .upsert(
                inactive_identity_id.as_str(),
                inactive_identity,
                Some(stored_project_identity.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .summarize_identity()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.users.total, 2);
        assert_eq!(summary.users.suspended, 1);
        assert_eq!(summary.users.active, 1);
        assert_eq!(summary.sessions.total, 2);
        assert_eq!(summary.sessions.active, 1);
        assert_eq!(summary.sessions.expired, 1);
        assert_eq!(summary.api_keys.total, 2);
        assert_eq!(summary.api_keys.active, 1);
        assert_eq!(summary.api_keys.inactive, 1);
        assert_eq!(summary.workload_identities.total, 3);
        assert_eq!(summary.workload_identities.active, 2);
        assert_eq!(summary.workload_identities.inactive, 1);
        assert_eq!(summary.workload_identities.unscoped, 1);
        assert_eq!(summary.workload_identities.by_project.len(), 1);
        assert_eq!(
            summary.workload_identities.by_project[0].project_id,
            project_id.to_string()
        );
        assert_eq!(summary.workload_identities.by_project[0].total, 2);
        assert_eq!(summary.workload_identities.by_project[0].active, 1);
        assert_eq!(summary.workload_identities.by_project[0].inactive, 1);
        assert_eq!(summary.credential_lifecycle.total, 12);
        assert_eq!(
            summary
                .credential_lifecycle
                .by_kind
                .iter()
                .map(|entry| (entry.kind, entry.total))
                .collect::<Vec<_>>(),
            vec![
                (IdentityCredentialLifecycleKind::Session, 2),
                (IdentityCredentialLifecycleKind::ApiKey, 2),
                (IdentityCredentialLifecycleKind::WorkloadToken, 3),
                (IdentityCredentialLifecycleKind::SecretVersion, 5),
            ]
        );
        assert_eq!(
            summary
                .credential_lifecycle
                .by_state
                .iter()
                .map(|entry| (entry.state, entry.total))
                .collect::<Vec<_>>(),
            vec![
                (IdentityCredentialLifecycleState::Active, 5),
                (IdentityCredentialLifecycleState::Inactive, 4),
                (IdentityCredentialLifecycleState::SuspendedOwner, 3),
            ]
        );
    }

    #[tokio::test]
    async fn credential_lifecycle_report_tracks_secret_versions_and_endpoint() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open_with_master_key(temp.path(), workload_identity_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let user_response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("lifecycle@example.com"),
                    display_name: String::from("Lifecycle User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let user_payload: Value = response_json(user_response).await;
        let user_id = user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing user id"))
            .to_owned();

        let _ = service
            .create_session(
                CreateSessionRequest {
                    email: String::from("lifecycle@example.com"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let api_key_response = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id: user_id.clone(),
                    name: String::from("lifecycle key"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let api_key_payload: Value = response_json(api_key_response).await;
        let api_key_id = api_key_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing api key id"))
            .to_owned();

        let workload_response = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:lifecycle-agent"),
                    display_name: String::from("Lifecycle Agent"),
                    project_id: None,
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workload_payload: CreateWorkloadIdentityResponse =
            response_json(workload_response).await;
        let identity_id = workload_payload.identity.id.clone();

        let stored_identity = service
            .workload_identities
            .get(&identity_id)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workload identity"));
        let now = OffsetDateTime::now_utc();
        let mut expiring_identity = stored_identity.value.clone();
        expiring_identity.credential.issued_at = now - Duration::seconds(800);
        expiring_identity.credential.expires_at = now + Duration::seconds(100);
        service
            .workload_identities
            .upsert(
                &identity_id,
                expiring_identity,
                Some(stored_identity.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let report = service
            .credential_lifecycle_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(report.summary.total, 5);
        assert_eq!(
            report
                .summary
                .by_kind
                .iter()
                .map(|entry| (entry.kind, entry.total))
                .collect::<Vec<_>>(),
            vec![
                (IdentityCredentialLifecycleKind::Session, 1),
                (IdentityCredentialLifecycleKind::ApiKey, 1),
                (IdentityCredentialLifecycleKind::WorkloadToken, 1),
                (IdentityCredentialLifecycleKind::SecretVersion, 2),
            ]
        );
        assert_eq!(
            report
                .summary
                .by_state
                .iter()
                .map(|entry| (entry.state, entry.total))
                .collect::<Vec<_>>(),
            vec![
                (IdentityCredentialLifecycleState::Active, 3),
                (IdentityCredentialLifecycleState::Expiring, 2),
            ]
        );

        let workload_entry = report
            .entries
            .iter()
            .find(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::WorkloadToken
                    && entry.id == identity_id
            })
            .unwrap_or_else(|| panic!("missing workload token entry"));
        assert_eq!(
            workload_entry.state,
            IdentityCredentialLifecycleState::Expiring
        );
        assert_eq!(
            workload_entry.principal_subject.as_deref(),
            Some("svc:lifecycle-agent")
        );

        let session_entry = report
            .entries
            .iter()
            .find(|entry| entry.kind == IdentityCredentialLifecycleKind::Session)
            .unwrap_or_else(|| panic!("missing session entry"));
        assert_eq!(
            session_entry.principal_subject.as_deref(),
            Some(format!("user:{user_id}").as_str())
        );

        let api_key_entry = report
            .entries
            .iter()
            .find(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::ApiKey && entry.id == api_key_id
            })
            .unwrap_or_else(|| panic!("missing api key entry"));
        assert_eq!(
            api_key_entry.principal_subject.as_deref(),
            Some(format!("user:{user_id}").as_str())
        );

        let api_key_secret_entry = report
            .entries
            .iter()
            .find(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::SecretVersion
                    && entry.source_id.as_deref() == Some(api_key_id.as_str())
            })
            .unwrap_or_else(|| panic!("missing api key secret version entry"));
        assert_eq!(
            api_key_secret_entry.source_kind,
            Some(IdentityCredentialSecretSourceKind::ApiKey)
        );
        assert_eq!(
            api_key_secret_entry.state,
            IdentityCredentialLifecycleState::Active
        );
        assert_eq!(api_key_secret_entry.version, Some(1));
        assert_eq!(
            api_key_secret_entry.secret_preview.as_deref(),
            api_key_payload["secret_preview"].as_str()
        );
        assert_eq!(
            api_key_secret_entry.principal_subject.as_deref(),
            Some(format!("user:{user_id}").as_str())
        );

        let workload_secret_entry = report
            .entries
            .iter()
            .find(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::SecretVersion
                    && entry.source_id.as_deref() == Some(identity_id.as_str())
            })
            .unwrap_or_else(|| panic!("missing workload secret version entry"));
        assert_eq!(
            workload_secret_entry.source_kind,
            Some(IdentityCredentialSecretSourceKind::WorkloadToken)
        );
        assert_eq!(
            workload_secret_entry.state,
            IdentityCredentialLifecycleState::Expiring
        );
        assert_eq!(workload_secret_entry.version, Some(1));
        assert_eq!(
            workload_secret_entry.secret_preview.as_deref(),
            Some(workload_payload.identity.credential.secret_preview.as_str())
        );

        let request = Request::builder()
            .method(Method::GET)
            .uri("/identity/credential-lifecycle")
            .body(Either::<Incoming, Full<Bytes>>::Right(Full::new(
                Bytes::new(),
            )))
            .unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .handle(request, operator_context())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing route response"));
        assert_eq!(response.status(), http::StatusCode::OK);

        let route_report: IdentityCredentialLifecycleReport = response_json(response).await;
        assert_eq!(route_report.summary, report.summary);
        assert_eq!(route_report.entries, report.entries);
    }

    #[tokio::test]
    async fn api_key_rotate_and_revoke_routes_advance_lifecycle_and_auth() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let user_response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("api-rotate@example.com"),
                    display_name: String::from("API Rotate User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let user_payload: Value = response_json(user_response).await;
        let user_id = user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing user id"))
            .to_owned();

        let api_key_response = service
            .create_api_key(
                CreateApiKeyRequest {
                    user_id: user_id.clone(),
                    name: String::from("rotate me"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let api_key_payload: Value = response_json(api_key_response).await;
        let api_key_id = api_key_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing api key id"))
            .to_owned();
        let issued_secret = api_key_payload["secret"]
            .as_str()
            .unwrap_or_else(|| panic!("missing issued api key secret"))
            .to_owned();
        let issued_secret_hash = sha256_hex(issued_secret.as_bytes());

        let rotate_request = Request::builder()
            .method(Method::POST)
            .uri(format!("/identity/api-keys/{api_key_id}/rotate"))
            .body(Either::<Incoming, Full<Bytes>>::Right(Full::new(
                Bytes::new(),
            )))
            .unwrap_or_else(|error| panic!("{error}"));
        let rotate_response = service
            .handle(rotate_request, operator_context())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing api key rotate response"));
        assert_eq!(rotate_response.status(), http::StatusCode::OK);
        let rotated_payload: Value = response_json(rotate_response).await;
        assert_eq!(rotated_payload["version"].as_u64(), Some(2));
        assert_eq!(rotated_payload["active"].as_bool(), Some(true));
        let rotated_secret = rotated_payload["secret"]
            .as_str()
            .unwrap_or_else(|| panic!("missing rotated api key secret"))
            .to_owned();
        assert_ne!(rotated_secret, issued_secret);

        let issued_index = service
            .api_keys_by_secret_hash
            .get(&issued_secret_hash)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing original api key hash index"));
        assert!(issued_index.deleted);

        assert!(
            service
                .authorize_bearer_token_for_service(&issued_secret, "governance")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        let rotated_principal = service
            .authorize_bearer_token_for_service(&rotated_secret, "governance")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("rotated api key should be admitted"));
        assert_eq!(rotated_principal.subject, format!("user:{user_id}"));

        let report = service
            .credential_lifecycle_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut secret_versions = report
            .entries
            .iter()
            .filter(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::SecretVersion
                    && entry.source_id.as_deref() == Some(api_key_id.as_str())
            })
            .collect::<Vec<_>>();
        secret_versions.sort_by_key(|entry| entry.version.unwrap_or_default());
        assert_eq!(secret_versions.len(), 2);
        assert_eq!(secret_versions[0].version, Some(1));
        assert_eq!(
            secret_versions[0].state,
            IdentityCredentialLifecycleState::Revoked
        );
        assert_eq!(secret_versions[1].version, Some(2));
        assert_eq!(
            secret_versions[1].state,
            IdentityCredentialLifecycleState::Active
        );
        assert_eq!(
            secret_versions[1].principal_subject.as_deref(),
            Some(format!("user:{user_id}").as_str())
        );

        let revoke_request = Request::builder()
            .method(Method::POST)
            .uri(format!("/identity/api-keys/{api_key_id}/revoke"))
            .body(Either::<Incoming, Full<Bytes>>::Right(Full::new(
                Bytes::new(),
            )))
            .unwrap_or_else(|error| panic!("{error}"));
        let revoke_response = service
            .handle(revoke_request, operator_context())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing api key revoke response"));
        assert_eq!(revoke_response.status(), http::StatusCode::OK);
        let revoked_payload: Value = response_json(revoke_response).await;
        assert_eq!(revoked_payload["active"].as_bool(), Some(false));
        assert_eq!(
            revoked_payload["metadata"]["lifecycle"].as_str(),
            Some("deleted")
        );

        assert!(
            service
                .authorize_bearer_token_for_service(&rotated_secret, "governance")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let revoked_report = service
            .credential_lifecycle_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let api_key_entry = revoked_report
            .entries
            .iter()
            .find(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::ApiKey && entry.id == api_key_id
            })
            .unwrap_or_else(|| panic!("missing api key lifecycle entry"));
        assert_eq!(
            api_key_entry.state,
            IdentityCredentialLifecycleState::Revoked
        );
        assert!(revoked_report.entries.iter().all(|entry| {
            entry.source_id.as_deref() != Some(api_key_id.as_str())
                || entry.state == IdentityCredentialLifecycleState::Revoked
        }));

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(outbox.iter().any(|message| {
            message.event_type.as_deref() == Some("identity.api_key.rotated.v1")
        }));
        assert!(outbox.iter().any(|message| {
            message.event_type.as_deref() == Some("identity.api_key.revoked.v1")
        }));
    }

    #[tokio::test]
    async fn workload_identity_rotate_and_revoke_routes_advance_lifecycle_and_auth() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open_with_master_key(temp.path(), workload_identity_key())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let issued_response = service
            .create_workload_identity(
                CreateWorkloadIdentityRequest {
                    subject: String::from("svc:rotate-agent"),
                    display_name: String::from("Rotate Agent"),
                    project_id: None,
                    workload_id: None,
                    audiences: vec![String::from("identity")],
                    ttl_seconds: Some(900),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let issued_payload: CreateWorkloadIdentityResponse = response_json(issued_response).await;
        let workload_identity_id = issued_payload.identity.id.clone();
        let issued_token = issued_payload.token.clone();

        let rotate_request = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "/identity/workload-identities/{workload_identity_id}/rotate"
            ))
            .body(Either::<Incoming, Full<Bytes>>::Right(Full::new(
                Bytes::new(),
            )))
            .unwrap_or_else(|error| panic!("{error}"));
        let rotate_response = service
            .handle(rotate_request, operator_context())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workload identity rotate response"));
        assert_eq!(rotate_response.status(), http::StatusCode::OK);
        let rotated_payload: CreateWorkloadIdentityResponse = response_json(rotate_response).await;
        assert_eq!(rotated_payload.identity.credential.version, 2);
        assert_ne!(rotated_payload.token, issued_token);

        assert!(
            service
                .authorize_bearer_token_for_service(&issued_token, "identity")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );
        let rotated_principal = service
            .authorize_bearer_token_for_service(&rotated_payload.token, "identity")
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("rotated workload token should be admitted"));
        assert_eq!(rotated_principal.subject, "svc:rotate-agent");

        let report = service
            .credential_lifecycle_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut secret_versions = report
            .entries
            .iter()
            .filter(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::SecretVersion
                    && entry.source_id.as_deref() == Some(workload_identity_id.as_str())
            })
            .collect::<Vec<_>>();
        secret_versions.sort_by_key(|entry| entry.version.unwrap_or_default());
        assert_eq!(secret_versions.len(), 2);
        assert_eq!(secret_versions[0].version, Some(1));
        assert_eq!(
            secret_versions[0].state,
            IdentityCredentialLifecycleState::Revoked
        );
        assert_eq!(secret_versions[1].version, Some(2));
        assert_eq!(
            secret_versions[1].state,
            IdentityCredentialLifecycleState::Active
        );
        assert_eq!(
            secret_versions[1].principal_subject.as_deref(),
            Some("svc:rotate-agent")
        );

        let revoke_request = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "/identity/workload-identities/{workload_identity_id}/revoke"
            ))
            .body(Either::<Incoming, Full<Bytes>>::Right(Full::new(
                Bytes::new(),
            )))
            .unwrap_or_else(|error| panic!("{error}"));
        let revoke_response = service
            .handle(revoke_request, operator_context())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing workload identity revoke response"));
        assert_eq!(revoke_response.status(), http::StatusCode::OK);
        let revoked_payload: Value = response_json(revoke_response).await;
        assert_eq!(revoked_payload["active"].as_bool(), Some(false));
        assert_eq!(
            revoked_payload["metadata"]["lifecycle"].as_str(),
            Some("deleted")
        );

        assert!(
            service
                .authorize_bearer_token_for_service(&rotated_payload.token, "identity")
                .await
                .unwrap_or_else(|error| panic!("{error}"))
                .is_none()
        );

        let revoked_report = service
            .credential_lifecycle_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let workload_entry = revoked_report
            .entries
            .iter()
            .find(|entry| {
                entry.kind == IdentityCredentialLifecycleKind::WorkloadToken
                    && entry.id == workload_identity_id
            })
            .unwrap_or_else(|| panic!("missing workload lifecycle entry"));
        assert_eq!(
            workload_entry.state,
            IdentityCredentialLifecycleState::Revoked
        );
        assert!(revoked_report.entries.iter().all(|entry| {
            entry.source_id.as_deref() != Some(workload_identity_id.as_str())
                || entry.state == IdentityCredentialLifecycleState::Revoked
        }));

        let outbox = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(outbox.iter().any(|message| {
            message.event_type.as_deref() == Some("identity.workload_identity.rotated.v1")
        }));
        assert!(outbox.iter().any(|message| {
            message.event_type.as_deref() == Some("identity.workload_identity.revoked.v1")
        }));
    }

    #[tokio::test]
    async fn session_route_allows_user_principals_while_lifecycle_report_stays_operator_only() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let user_response = service
            .create_user(
                CreateUserRequest {
                    email: String::from("route-session@example.com"),
                    display_name: String::from("Route Session User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let user_payload: Value = response_json(user_response).await;
        let user_id = user_payload["id"]
            .as_str()
            .unwrap_or_else(|| panic!("missing user id"))
            .to_owned();

        let request = Request::builder()
            .method(Method::POST)
            .uri("/identity/sessions")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Either::<Incoming, Full<Bytes>>::Right(Full::new(
                Bytes::from(
                    serde_json::to_vec(&CreateSessionRequest {
                        email: String::from("route-session@example.com"),
                        password: String::from("pw"),
                    })
                    .unwrap_or_else(|error| panic!("{error}")),
                ),
            )))
            .unwrap_or_else(|error| panic!("{error}"));
        let user_context = RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(
                PrincipalKind::User,
                format!("user:{user_id}"),
            ));
        let response = service
            .handle(request, user_context)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing session route response"));
        assert_eq!(response.status(), http::StatusCode::CREATED);

        let lifecycle_request = Request::builder()
            .method(Method::GET)
            .uri("/identity/credential-lifecycle")
            .body(Either::<Incoming, Full<Bytes>>::Right(Full::new(
                Bytes::new(),
            )))
            .unwrap_or_else(|error| panic!("{error}"));
        let error = service
            .handle(
                lifecycle_request,
                RequestContext::new()
                    .unwrap_or_else(|error| panic!("{error}"))
                    .with_principal(PrincipalIdentity::new(
                        PrincipalKind::User,
                        format!("user:{user_id}"),
                    )),
            )
            .await
            .expect_err("user principals should not read operator credential reports");
        assert_eq!(error.code, ErrorCode::Forbidden);
        assert_eq!(
            error.message,
            "identity administration requires an operator principal"
        );
    }

    #[tokio::test]
    async fn migrated_user_metadata_preserves_optimistic_concurrency() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = IdentityService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_user(
                CreateUserRequest {
                    email: String::from("concurrency@example.com"),
                    display_name: String::from("Concurrency User"),
                    password: String::from("pw"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let (user_id, stored) = service
            .users
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("missing stored user"));
        let mut user = stored.value.clone();
        user.display_name = String::from("Updated User");

        let updated = service
            .users
            .upsert(&user_id, user.clone(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(updated.version, stored.version + 1);

        let stale = service
            .users
            .upsert(&user_id, user, Some(stored.version))
            .await
            .expect_err("stale version should fail");
        assert_eq!(stale.code, uhost_core::ErrorCode::Conflict);
    }
}
