//! Policy and approvals service.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{
    PlatformError, PrincipalIdentity, RequestContext, Result, normalize_label_key, sha256_hex,
    validate_label_value, validate_slug,
};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, DurableOutbox};
use uhost_types::{
    ApprovalId, AuditActor, AuditId, EventHeader, EventPayload, OwnershipScope, PlatformEvent,
    PolicyId, PrincipalKind, ResourceMetadata, ServiceEvent,
};

/// Policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub id: PolicyId,
    pub resource_kind: String,
    pub action: String,
    pub effect: String,
    pub selector: BTreeMap<String, String>,
    pub metadata: ResourceMetadata,
}

/// Approval workflow record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub id: ApprovalId,
    pub subject: String,
    pub required_approvers: u16,
    pub approved: bool,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreatePolicyRequest {
    resource_kind: String,
    action: String,
    effect: String,
    selector: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateApprovalRequest {
    subject: String,
    required_approvers: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EvaluatePolicyRequest {
    resource_kind: String,
    action: String,
    selector: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SummaryCounter {
    key: String,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicySummaryResponse {
    policies: PolicySummaryCounts,
    approvals: ApprovalSummaryCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PolicySummaryCounts {
    total: usize,
    allow: usize,
    deny: usize,
    by_resource_kind: Vec<SummaryCounter>,
    by_action: Vec<SummaryCounter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ApprovalSummaryCounts {
    total: usize,
    approved: usize,
    pending: usize,
    by_required_approvers: Vec<SummaryCounter>,
}

/// Policy evaluation result with structured explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatePolicyResponse {
    /// Final decision after evaluating matching rules.
    pub decision: String,
    /// Structured explanation describing why the decision was produced.
    pub explanation: PolicyDecisionExplanation,
}

/// Structured explanation for one policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecisionExplanation {
    /// Normalized resource kind evaluated for the request.
    pub evaluated_resource_kind: String,
    /// Normalized action evaluated for the request.
    pub evaluated_action: String,
    /// Exact input fields that contributed to one or more matching rules.
    pub matched_inputs: BTreeMap<String, String>,
    /// All policy identifiers whose selectors matched the request.
    pub matched_policy_ids: Vec<String>,
    /// Matching policy identifiers that determined the final decision.
    pub decisive_policy_ids: Vec<String>,
    /// Human-readable explanation of the decision path.
    pub rationale: String,
    /// Per-rule breakdown for every matched policy.
    pub rule_evaluations: Vec<PolicyRuleEvaluation>,
    /// Authenticated actor bound to the request when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Typed principal context bound to the request when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalIdentity>,
}

/// Rule-level explanation for one matched policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRuleEvaluation {
    /// Matched policy identifier.
    pub policy_id: String,
    /// Effect contributed by the matched policy.
    pub effect: String,
    /// Selector entries from the policy that matched the request.
    pub matched_selector: BTreeMap<String, String>,
}

/// Policy service.
#[derive(Debug, Clone)]
pub struct PolicyService {
    policies: DocumentStore<PolicyRecord>,
    approvals: DocumentStore<ApprovalRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

impl PolicyService {
    /// Open policy state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("policy");
        Ok(Self {
            policies: DocumentStore::open(root.join("policies.json")).await?,
            approvals: DocumentStore::open(root.join("approvals.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        })
    }

    async fn create_policy(
        &self,
        request: CreatePolicyRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        require_non_workload_principal_or_local_dev(context, "policy mutation")?;
        let request = validate_policy_request(request)?;
        let id = PolicyId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate policy id")
                .with_detail(error.to_string())
        })?;
        let record = PolicyRecord {
            id: id.clone(),
            resource_kind: request.resource_kind,
            action: request.action,
            effect: request.effect,
            selector: request.selector,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.policies.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "policy.policy.created.v1",
            "policy",
            id.as_str(),
            "created",
            serde_json::json!({
                "resource_kind": record.resource_kind.clone(),
                "action": record.action.clone(),
                "effect": record.effect.clone(),
                "selector": record.selector.clone(),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_approval(
        &self,
        request: CreateApprovalRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        require_non_workload_principal_or_local_dev(context, "policy approval management")?;
        let request = validate_approval_request(request)?;
        let id = ApprovalId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate approval id")
                .with_detail(error.to_string())
        })?;
        let record = ApprovalRecord {
            id: id.clone(),
            subject: request.subject,
            required_approvers: request.required_approvers,
            approved: false,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.approvals.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "policy.approval.created.v1",
            "approval",
            id.as_str(),
            "created",
            serde_json::json!({
                "subject": record.subject.clone(),
                "required_approvers": record.required_approvers,
                "approved": record.approved,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn evaluate_policy(
        &self,
        request: EvaluatePolicyRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let request = validate_policy_evaluation_request(request)?;
        let mut matches = self
            .policies
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|policy| policy.resource_kind == request.resource_kind)
            .filter(|policy| policy.action == request.action)
            .filter(|policy| policy_selector_matches(&policy.selector, &request.selector))
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            policy_effect_precedence(&left.effect)
                .cmp(&policy_effect_precedence(&right.effect))
                .then_with(|| right.selector.len().cmp(&left.selector.len()))
                .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
        });

        let deny_count = matches
            .iter()
            .filter(|policy| policy.effect == "deny")
            .count();
        let allow_count = matches
            .iter()
            .filter(|policy| policy.effect == "allow")
            .count();
        let decision = if deny_count > 0 {
            "deny"
        } else if allow_count > 0 {
            "allow"
        } else {
            "deny"
        };

        let matched_policy_ids = matches
            .iter()
            .map(|policy| policy.id.to_string())
            .collect::<Vec<_>>();
        let decisive_policy_ids = matches
            .iter()
            .filter(|policy| policy.effect == decision)
            .map(|policy| policy.id.to_string())
            .collect::<Vec<_>>();
        let rationale = if deny_count > 0 && allow_count > 0 {
            String::from("matched deny policies override matched allow policies")
        } else if deny_count > 0 {
            String::from("matched deny policies blocked the request")
        } else if allow_count > 0 {
            String::from("matched allow policies permitted the request")
        } else {
            String::from("no policy matched resource/action/selector; default deny applied")
        };
        let matched_inputs = matched_inputs_for_evaluation(&request, &matches);
        let rule_evaluations = matches
            .into_iter()
            .map(|policy| PolicyRuleEvaluation {
                policy_id: policy.id.to_string(),
                effect: policy.effect,
                matched_selector: policy.selector,
            })
            .collect::<Vec<_>>();
        let evaluation = EvaluatePolicyResponse {
            decision: decision.to_owned(),
            explanation: PolicyDecisionExplanation {
                evaluated_resource_kind: request.resource_kind,
                evaluated_action: request.action,
                matched_inputs,
                matched_policy_ids,
                decisive_policy_ids,
                rationale,
                rule_evaluations,
                actor: context.actor.clone(),
                principal: context.principal.clone(),
            },
        };
        self.append_event(
            "policy.evaluated.v1",
            "policy_evaluation",
            &context.request_id,
            "evaluated",
            serde_json::json!({
                "decision": evaluation.decision.clone(),
                "explanation": evaluation.explanation.clone(),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &evaluation)
    }

    async fn summary_report(&self) -> Result<http::Response<ApiBody>> {
        let policies = self
            .policies
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let policy_allow = policies
            .iter()
            .filter(|policy| policy.effect == "allow")
            .count();
        let policy_deny = policies
            .iter()
            .filter(|policy| policy.effect == "deny")
            .count();
        let mut by_resource_kind = BTreeMap::<String, usize>::new();
        let mut by_action = BTreeMap::<String, usize>::new();
        for policy in &policies {
            let resource_entry = by_resource_kind
                .entry(policy.resource_kind.clone())
                .or_insert(0);
            *resource_entry += 1;
            let action_entry = by_action.entry(policy.action.clone()).or_insert(0);
            *action_entry += 1;
        }

        let approvals = self
            .approvals
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .collect::<Vec<_>>();
        let approvals_approved = approvals
            .iter()
            .filter(|approval| approval.approved)
            .count();
        let mut by_required_approvers = BTreeMap::<String, usize>::new();
        for approval in &approvals {
            let entry = by_required_approvers
                .entry(approval.required_approvers.to_string())
                .or_insert(0);
            *entry += 1;
        }

        let summary = PolicySummaryResponse {
            policies: PolicySummaryCounts {
                total: policies.len(),
                allow: policy_allow,
                deny: policy_deny,
                by_resource_kind: map_summary_counters(by_resource_kind),
                by_action: map_summary_counters(by_action),
            },
            approvals: ApprovalSummaryCounts {
                total: approvals.len(),
                approved: approvals_approved,
                pending: approvals.len().saturating_sub(approvals_approved),
                by_required_approvers: map_summary_counters(by_required_approvers),
            },
        };
        json_response(StatusCode::OK, &summary)
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
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("policy"),
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
            .enqueue("policy.events.v1", event, Some(&idempotency))
            .await?;
        Ok(())
    }
}

fn validate_policy_request(mut request: CreatePolicyRequest) -> Result<CreatePolicyRequest> {
    request.resource_kind = normalize_policy_token("resource_kind", &request.resource_kind)?;
    request.action = normalize_policy_token("action", &request.action)?;
    request.effect = normalize_policy_effect(&request.effect)?;
    request.selector = normalize_policy_selector(request.selector)?;
    Ok(request)
}

fn validate_approval_request(mut request: CreateApprovalRequest) -> Result<CreateApprovalRequest> {
    let subject = request.subject.trim();
    if subject.is_empty() {
        return Err(PlatformError::invalid("subject may not be empty"));
    }

    if request.required_approvers == 0 {
        return Err(PlatformError::invalid(
            "required_approvers must be at least 1",
        ));
    }

    request.subject = subject.to_owned();
    Ok(request)
}

fn validate_policy_evaluation_request(
    mut request: EvaluatePolicyRequest,
) -> Result<EvaluatePolicyRequest> {
    request.resource_kind = normalize_policy_token("resource_kind", &request.resource_kind)?;
    request.action = normalize_policy_token("action", &request.action)?;
    request.selector = normalize_policy_selector(request.selector)?;
    Ok(request)
}

fn normalize_policy_token(field: &'static str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }

    validate_slug(&normalized).map_err(|error| {
        PlatformError::invalid(format!("{field} is invalid")).with_detail(error.to_string())
    })
}

fn normalize_policy_effect(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "allow" | "deny" => Ok(normalized),
        _ => Err(PlatformError::invalid("effect must be `allow` or `deny`")),
    }
}

fn normalize_policy_selector(
    selector: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut normalized = BTreeMap::new();

    for (key, value) in selector {
        let normalized_key = normalize_label_key(&key).map_err(|error| {
            PlatformError::invalid("selector key is invalid").with_detail(error.to_string())
        })?;
        let trimmed_value = value.trim();
        if trimmed_value.is_empty() {
            return Err(PlatformError::invalid("selector values may not be empty"));
        }

        let normalized_value = validate_label_value(trimmed_value).map_err(|error| {
            PlatformError::invalid("selector value is invalid").with_detail(error.to_string())
        })?;

        normalized.insert(normalized_key, normalized_value);
    }

    Ok(normalized)
}

fn policy_selector_matches(
    policy_selector: &BTreeMap<String, String>,
    request_selector: &BTreeMap<String, String>,
) -> bool {
    policy_selector
        .iter()
        .all(|(key, value)| request_selector.get(key) == Some(value))
}

fn policy_effect_precedence(effect: &str) -> u8 {
    match effect {
        "deny" => 0,
        "allow" => 1,
        _ => 2,
    }
}

fn matched_inputs_for_evaluation(
    request: &EvaluatePolicyRequest,
    policies: &[PolicyRecord],
) -> BTreeMap<String, String> {
    let mut matched_inputs = BTreeMap::new();
    if policies.is_empty() {
        return matched_inputs;
    }

    matched_inputs.insert(String::from("resource_kind"), request.resource_kind.clone());
    matched_inputs.insert(String::from("action"), request.action.clone());
    for policy in policies {
        for key in policy.selector.keys() {
            if let Some(value) = request.selector.get(key) {
                matched_inputs.insert(format!("selector.{key}"), value.clone());
            }
        }
    }

    matched_inputs
}

fn map_summary_counters(counters: BTreeMap<String, usize>) -> Vec<SummaryCounter> {
    counters
        .into_iter()
        .map(|(key, count)| SummaryCounter { key, count })
        .collect::<Vec<_>>()
}

impl HttpService for PolicyService {
    fn name(&self) -> &'static str {
        "policy"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/policy")];
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
                (Method::GET, ["policy"]) => {
                    require_non_workload_principal_or_local_dev(&context, "policy control plane")?;
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({
                            "service": self.name(),
                            "state_root": self.state_root,
                        }),
                    )
                    .map(Some)
                }
                (Method::GET, ["policy", "policies"]) => {
                    require_non_workload_principal_or_local_dev(&context, "policy control plane")?;
                    let values = self
                        .policies
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["policy", "summary"]) => {
                    require_non_workload_principal_or_local_dev(&context, "policy control plane")?;
                    self.summary_report().await.map(Some)
                }
                (Method::GET, ["policy", "outbox"]) => {
                    require_non_workload_principal_or_local_dev(&context, "policy control plane")?;
                    let messages = self.outbox.list_all().await?;
                    json_response(StatusCode::OK, &messages).map(Some)
                }
                (Method::POST, ["policy", "policies"]) => {
                    let body: CreatePolicyRequest = parse_json(request).await?;
                    self.create_policy(body, &context).await.map(Some)
                }
                (Method::GET, ["policy", "approvals"]) => {
                    require_non_workload_principal_or_local_dev(
                        &context,
                        "policy approval management",
                    )?;
                    let values = self
                        .approvals
                        .list()
                        .await?
                        .into_iter()
                        .map(|(_, record)| record.value)
                        .collect::<Vec<_>>();
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["policy", "approvals"]) => {
                    let body: CreateApprovalRequest = parse_json(request).await?;
                    self.create_approval(body, &context).await.map(Some)
                }
                (Method::POST, ["policy", "evaluate"]) => {
                    let body: EvaluatePolicyRequest = parse_json(request).await?;
                    self.evaluate_policy(body, &context).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::{
        CreateApprovalRequest, CreatePolicyRequest, EvaluatePolicyRequest, EvaluatePolicyResponse,
        PolicyRecord, PolicyService,
    };
    use http::StatusCode;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use uhost_core::{PrincipalIdentity, PrincipalKind, RequestContext};

    async fn test_service() -> (TempDir, PolicyService) {
        let dir = tempfile::tempdir().unwrap();
        let service = PolicyService::open(dir.path()).await.unwrap();
        (dir, service)
    }

    async fn response_json<T: serde::de::DeserializeOwned>(
        response: http::Response<uhost_api::ApiBody>,
    ) -> T {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn evaluation_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(
                PrincipalIdentity::new(PrincipalKind::Workload, "svc:deploy-bot")
                    .with_credential_id("wid_demo"),
            )
    }

    fn operator_context() -> RequestContext {
        RequestContext::new()
            .unwrap_or_else(|error| panic!("{error}"))
            .with_principal(PrincipalIdentity::new(
                PrincipalKind::Operator,
                "bootstrap_admin",
            ))
    }

    #[tokio::test]
    async fn policy_creation_normalizes_inputs() {
        let (_dir, service) = test_service().await;
        let context = operator_context();
        let response = service
            .create_policy(
                CreatePolicyRequest {
                    resource_kind: " Service ".to_owned(),
                    action: " CREATE ".to_owned(),
                    effect: "ALLOW".to_owned(),
                    selector: BTreeMap::from([(String::from("Env"), String::from("prod"))]),
                },
                &context,
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let record: PolicyRecord = response_json(response).await;
        assert_eq!(record.resource_kind, "service");
        assert_eq!(record.action, "create");
        assert_eq!(record.effect, "allow");
        assert_eq!(
            record.selector,
            BTreeMap::from([(String::from("env"), String::from("prod"))])
        );
    }

    #[tokio::test]
    async fn policy_creation_rejects_unknown_effect() {
        let (_dir, service) = test_service().await;
        let context = operator_context();
        let error = service
            .create_policy(
                CreatePolicyRequest {
                    resource_kind: "service".to_owned(),
                    action: "create".to_owned(),
                    effect: "audit".to_owned(),
                    selector: BTreeMap::new(),
                },
                &context,
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert_eq!(error.message, "effect must be `allow` or `deny`");
    }

    #[tokio::test]
    async fn approval_creation_rejects_zero_required_approvers() {
        let (_dir, service) = test_service().await;
        let context = operator_context();
        let error = service
            .create_approval(
                CreateApprovalRequest {
                    subject: "change-window".to_owned(),
                    required_approvers: 0,
                },
                &context,
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert_eq!(error.message, "required_approvers must be at least 1");
    }

    #[tokio::test]
    async fn policy_evaluation_returns_structured_explanation_and_principal_context() {
        let (_dir, service) = test_service().await;
        let operator_context = operator_context();
        let allow: PolicyRecord = response_json(
            service
                .create_policy(
                    CreatePolicyRequest {
                        resource_kind: String::from("service"),
                        action: String::from("deploy"),
                        effect: String::from("allow"),
                        selector: BTreeMap::from([
                            (String::from("env"), String::from("prod")),
                            (String::from("team"), String::from("payments")),
                        ]),
                    },
                    &operator_context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let deny: PolicyRecord = response_json(
            service
                .create_policy(
                    CreatePolicyRequest {
                        resource_kind: String::from("service"),
                        action: String::from("deploy"),
                        effect: String::from("deny"),
                        selector: BTreeMap::from([
                            (String::from("env"), String::from("prod")),
                            (String::from("compliance"), String::from("blocked")),
                        ]),
                    },
                    &operator_context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let response = service
            .evaluate_policy(
                EvaluatePolicyRequest {
                    resource_kind: String::from("service"),
                    action: String::from("deploy"),
                    selector: BTreeMap::from([
                        (String::from("env"), String::from("prod")),
                        (String::from("team"), String::from("payments")),
                        (String::from("compliance"), String::from("blocked")),
                    ]),
                },
                &evaluation_context(),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(response.status(), StatusCode::OK);
        let evaluation: EvaluatePolicyResponse = response_json(response).await;
        assert_eq!(evaluation.decision, "deny");
        assert_eq!(evaluation.explanation.evaluated_resource_kind, "service");
        assert_eq!(evaluation.explanation.evaluated_action, "deploy");
        assert_eq!(
            evaluation.explanation.matched_policy_ids,
            vec![deny.id.to_string(), allow.id.to_string()]
        );
        assert_eq!(
            evaluation.explanation.decisive_policy_ids,
            vec![deny.id.to_string()]
        );
        assert_eq!(
            evaluation.explanation.matched_inputs,
            BTreeMap::from([
                (String::from("action"), String::from("deploy")),
                (String::from("resource_kind"), String::from("service")),
                (String::from("selector.compliance"), String::from("blocked"),),
                (String::from("selector.env"), String::from("prod")),
                (String::from("selector.team"), String::from("payments")),
            ])
        );
        assert_eq!(
            evaluation.explanation.rationale,
            "matched deny policies override matched allow policies"
        );
        assert_eq!(evaluation.explanation.rule_evaluations.len(), 2);
        assert_eq!(
            evaluation.explanation.rule_evaluations[0].policy_id,
            deny.id.to_string()
        );
        assert_eq!(evaluation.explanation.rule_evaluations[0].effect, "deny");
        assert_eq!(
            evaluation.explanation.actor.as_deref(),
            Some("svc:deploy-bot")
        );
        let principal = evaluation
            .explanation
            .principal
            .unwrap_or_else(|| panic!("missing principal context"));
        assert_eq!(principal.kind, PrincipalKind::Workload);
        assert_eq!(principal.subject, "svc:deploy-bot");
        assert_eq!(principal.credential_id.as_deref(), Some("wid_demo"));
    }

    #[tokio::test]
    async fn policy_mutations_and_evaluations_append_durable_audit_and_outbox_events() {
        let (dir, service) = test_service().await;
        let operator_context = operator_context();
        let evaluation_context = evaluation_context();

        let _policy: PolicyRecord = response_json(
            service
                .create_policy(
                    CreatePolicyRequest {
                        resource_kind: String::from("service"),
                        action: String::from("deploy"),
                        effect: String::from("allow"),
                        selector: BTreeMap::from([(String::from("env"), String::from("prod"))]),
                    },
                    &operator_context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _approval: super::ApprovalRecord = response_json(
            service
                .create_approval(
                    CreateApprovalRequest {
                        subject: String::from("maintenance-window"),
                        required_approvers: 2,
                    },
                    &operator_context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _evaluation: EvaluatePolicyResponse = response_json(
            service
                .evaluate_policy(
                    EvaluatePolicyRequest {
                        resource_kind: String::from("service"),
                        action: String::from("deploy"),
                        selector: BTreeMap::from([(String::from("env"), String::from("prod"))]),
                    },
                    &evaluation_context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let messages = service
            .outbox
            .list_all()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(messages.len(), 3);
        let event_types = messages
            .iter()
            .map(|message| message.payload.header.event_type.clone())
            .collect::<Vec<_>>();
        assert!(event_types.contains(&String::from("policy.policy.created.v1")));
        assert!(event_types.contains(&String::from("policy.approval.created.v1")));
        assert!(event_types.contains(&String::from("policy.evaluated.v1")));

        let audit_log = fs::read_to_string(dir.path().join("policy").join("audit.log"))
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(audit_log.contains("policy.policy.created.v1"));
        assert!(audit_log.contains("policy.approval.created.v1"));
        assert!(audit_log.contains("policy.evaluated.v1"));
    }

    #[tokio::test]
    async fn summary_report_reflects_persisted_policy_and_approval_records() {
        let (_dir, service) = test_service().await;
        let context = operator_context();

        let _allow_policy: PolicyRecord = response_json(
            service
                .create_policy(
                    CreatePolicyRequest {
                        resource_kind: String::from("service"),
                        action: String::from("deploy"),
                        effect: String::from("allow"),
                        selector: BTreeMap::from([(String::from("env"), String::from("prod"))]),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _deny_policy: PolicyRecord = response_json(
            service
                .create_policy(
                    CreatePolicyRequest {
                        resource_kind: String::from("node"),
                        action: String::from("delete"),
                        effect: String::from("deny"),
                        selector: BTreeMap::from([(String::from("tier"), String::from("core"))]),
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let approval_a: super::ApprovalRecord = response_json(
            service
                .create_approval(
                    CreateApprovalRequest {
                        subject: String::from("maintenance-window"),
                        required_approvers: 2,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let _approval_b: super::ApprovalRecord = response_json(
            service
                .create_approval(
                    CreateApprovalRequest {
                        subject: String::from("schema-migration"),
                        required_approvers: 3,
                    },
                    &context,
                )
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let stored = service
            .approvals
            .get(approval_a.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing approval"));
        let mut updated = stored.value;
        updated.approved = true;
        let _ = service
            .approvals
            .upsert(approval_a.id.as_str(), updated, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .summary_report()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::OK);
        let summary: serde_json::Value = response_json(response).await;

        assert_eq!(summary["policies"]["total"], 2);
        assert_eq!(summary["policies"]["allow"], 1);
        assert_eq!(summary["policies"]["deny"], 1);
        assert_eq!(summary["approvals"]["total"], 2);
        assert_eq!(summary["approvals"]["approved"], 1);
        assert_eq!(summary["approvals"]["pending"], 1);

        let by_resource = summary["policies"]["by_resource_kind"]
            .as_array()
            .unwrap_or_else(|| panic!("expected by_resource_kind array"));
        let service_count = by_resource
            .iter()
            .find(|entry| entry["key"] == "service")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(service_count, 1);

        let by_required = summary["approvals"]["by_required_approvers"]
            .as_array()
            .unwrap_or_else(|| panic!("expected by_required_approvers array"));
        let approver_two = by_required
            .iter()
            .find(|entry| entry["key"] == "2")
            .and_then(|entry| entry["count"].as_u64())
            .unwrap_or_default();
        assert_eq!(approver_two, 1);
    }
}
