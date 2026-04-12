use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{HeaderName, HeaderValue, Method, Response, StatusCode};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use uhost_api::{ApiBody, full_body};
use uhost_core::{
    ErrorCode, PlatformError, PrincipalIdentity, PrincipalKind, RequestContext, Result, sha256_hex,
};
use uhost_store::{DocumentStore, StoredDocument};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HttpIdempotencyRecord {
    principal_kind: Option<PrincipalKind>,
    principal_subject: String,
    route: String,
    request_digest: String,
    idempotency_key: String,
    scope_key: String,
    method: String,
    state: HttpIdempotencyState,
    response: Option<StoredHttpResponse>,
    correlation_id: String,
    request_id: String,
    created_at: OffsetDateTime,
    completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HttpIdempotencyState {
    InFlight,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredHttpResponse {
    status: u16,
    headers: Vec<StoredHttpHeader>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StoredHttpHeader {
    name: String,
    value: String,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedIdempotencyRequest {
    principal_kind: Option<PrincipalKind>,
    principal_subject: String,
    route: String,
    request_digest: String,
    idempotency_key: String,
    scope_key: String,
    journal_key: String,
    method: Method,
    correlation_id: String,
    request_id: String,
}

impl PreparedIdempotencyRequest {
    pub(crate) fn from_context(
        route: impl Into<String>,
        request_digest: impl Into<String>,
        idempotency_key: impl Into<String>,
        method: &Method,
        context: &RequestContext,
    ) -> Self {
        let route = route.into();
        let request_digest = request_digest.into();
        let idempotency_key = idempotency_key.into();
        let (principal_kind, principal_subject) =
            principal_key_material(context.principal.as_ref());
        let scope_key = idempotency_scope_key(
            &principal_kind,
            &principal_subject,
            &route,
            &idempotency_key,
        );
        let journal_key = idempotency_journal_key(&scope_key, &request_digest);

        Self {
            principal_kind,
            principal_subject,
            route,
            request_digest,
            idempotency_key,
            scope_key,
            journal_key,
            method: method.clone(),
            correlation_id: context.correlation_id.clone(),
            request_id: context.request_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PendingJournalEntry {
    key: String,
    version: u64,
    record: HttpIdempotencyRecord,
}

pub(crate) enum JournalBeginOutcome {
    Proceed(PendingJournalEntry),
    Replay(Response<ApiBody>),
}

/// Durable HTTP idempotency journal used by the runtime dispatcher.
#[derive(Clone)]
pub struct HttpIdempotencyJournal {
    store: DocumentStore<HttpIdempotencyRecord>,
    gate: Arc<Mutex<()>>,
}

impl HttpIdempotencyJournal {
    /// Open or create the journal at the supplied path.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Self {
            store: DocumentStore::open(path).await?,
            gate: Arc::new(Mutex::new(())),
        })
    }

    pub(crate) async fn begin(
        &self,
        request: PreparedIdempotencyRequest,
    ) -> Result<JournalBeginOutcome> {
        let _guard = self.gate.lock().await;
        if let Some(existing) = self.store.get(&request.journal_key).await? {
            return existing_outcome(existing);
        }

        let existing_scope = self
            .store
            .list()
            .await?
            .into_iter()
            .find_map(|(_, document)| {
                if document.deleted || document.value.scope_key != request.scope_key {
                    return None;
                }
                Some(document)
            });
        if let Some(existing) = existing_scope {
            return Err(scope_conflict_error(
                &existing.value,
                &request.request_digest,
            ));
        }

        let now = OffsetDateTime::now_utc();
        let record = HttpIdempotencyRecord {
            principal_kind: request.principal_kind,
            principal_subject: request.principal_subject,
            route: request.route,
            request_digest: request.request_digest,
            idempotency_key: request.idempotency_key,
            scope_key: request.scope_key,
            method: request.method.as_str().to_owned(),
            state: HttpIdempotencyState::InFlight,
            response: None,
            correlation_id: request.correlation_id,
            request_id: request.request_id,
            created_at: now,
            completed_at: None,
        };

        match self
            .store
            .create(&request.journal_key, record.clone())
            .await
        {
            Ok(stored) => Ok(JournalBeginOutcome::Proceed(PendingJournalEntry {
                key: request.journal_key,
                version: stored.version,
                record,
            })),
            Err(error) if error.code == ErrorCode::Conflict => {
                let Some(existing) = self.store.get(&request.journal_key).await? else {
                    return Err(error);
                };
                existing_outcome(existing)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) async fn complete(
        &self,
        pending: PendingJournalEntry,
        response: StoredHttpResponse,
    ) -> Result<()> {
        let _guard = self.gate.lock().await;
        let mut record = pending.record;
        record.state = HttpIdempotencyState::Completed;
        record.response = Some(response);
        record.completed_at = Some(OffsetDateTime::now_utc());
        self.store
            .upsert(&pending.key, record, Some(pending.version))
            .await?;
        Ok(())
    }
}

impl StoredHttpResponse {
    pub(crate) async fn capture(response: Response<ApiBody>) -> Result<(Self, Response<ApiBody>)> {
        let (parts, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|error| {
                PlatformError::new(
                    ErrorCode::Internal,
                    "failed to capture idempotent response body",
                )
                .with_detail(error.to_string())
            })?
            .to_bytes()
            .to_vec();

        let headers = parts
            .headers
            .iter()
            .filter_map(|(name, value)| {
                if is_hop_by_hop_header(name) {
                    return None;
                }
                value.to_str().ok().map(|value| StoredHttpHeader {
                    name: name.as_str().to_owned(),
                    value: value.to_owned(),
                })
            })
            .collect();

        let stored = Self {
            status: parts.status.as_u16(),
            headers,
            body,
        };
        let response = stored.to_response()?;
        Ok((stored, response))
    }

    fn to_response(&self) -> Result<Response<ApiBody>> {
        let status = StatusCode::from_u16(self.status).map_err(|error| {
            PlatformError::new(
                ErrorCode::Internal,
                "stored idempotent response has invalid status code",
            )
            .with_detail(error.to_string())
        })?;
        let mut builder = Response::builder().status(status);
        for header in &self.headers {
            let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|error| {
                PlatformError::new(
                    ErrorCode::Internal,
                    "stored idempotent response has invalid header name",
                )
                .with_detail(error.to_string())
            })?;
            let value = HeaderValue::from_str(&header.value).map_err(|error| {
                PlatformError::new(
                    ErrorCode::Internal,
                    "stored idempotent response has invalid header value",
                )
                .with_detail(error.to_string())
            })?;
            builder = builder.header(name, value);
        }
        builder
            .body(full_body(Bytes::from(self.body.clone())))
            .map_err(|error| {
                PlatformError::new(
                    ErrorCode::Internal,
                    "failed to rebuild stored idempotent response",
                )
                .with_detail(error.to_string())
            })
    }
}

fn existing_outcome(
    existing: StoredDocument<HttpIdempotencyRecord>,
) -> Result<JournalBeginOutcome> {
    match existing.value.state {
        HttpIdempotencyState::Completed => existing
            .value
            .response
            .as_ref()
            .ok_or_else(|| {
                PlatformError::new(
                    ErrorCode::Internal,
                    "completed idempotency record is missing stored response",
                )
            })
            .and_then(StoredHttpResponse::to_response)
            .map(JournalBeginOutcome::Replay),
        HttpIdempotencyState::InFlight => Err(PlatformError::conflict(
            "idempotent request is already in progress",
        )
        .with_detail(format!(
            "route={} idempotency_key={}",
            existing.value.route, existing.value.idempotency_key
        ))),
    }
}

fn scope_conflict_error(existing: &HttpIdempotencyRecord, request_digest: &str) -> PlatformError {
    PlatformError::conflict("idempotency key already used for different request").with_detail(
        format!(
            "route={} method={} existing_digest={} request_digest={request_digest}",
            existing.route, existing.method, existing.request_digest
        ),
    )
}

fn principal_key_material(
    principal: Option<&PrincipalIdentity>,
) -> (Option<PrincipalKind>, String) {
    match principal {
        Some(principal) => (Some(principal.kind), principal.subject.clone()),
        None => (None, String::from("anonymous")),
    }
}

fn idempotency_scope_key(
    principal_kind: &Option<PrincipalKind>,
    principal_subject: &str,
    route: &str,
    idempotency_key: &str,
) -> String {
    let principal_scope = principal_kind
        .map(PrincipalKind::as_str)
        .unwrap_or("anonymous");
    sha256_hex(
        format!(
            "runtime-http-idempotency-scope:v1|{principal_scope}|{principal_subject}|{route}|{idempotency_key}"
        )
        .as_bytes(),
    )
}

fn idempotency_journal_key(scope_key: &str, request_digest: &str) -> String {
    sha256_hex(format!("runtime-http-idempotency-entry:v1|{scope_key}|{request_digest}").as_bytes())
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(*name, CONNECTION | CONTENT_LENGTH | TRANSFER_ENCODING)
}
