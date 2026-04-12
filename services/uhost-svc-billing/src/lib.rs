//! Billing and subscriptions service.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex, validate_slug};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::DocumentStore;
use uhost_types::{
    AuditId, BillingAccountId, InvoiceId, OwnershipScope, ResourceMetadata, SubscriptionId,
};

/// Billing account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BillingAccount {
    pub id: BillingAccountId,
    pub owner_id: String,
    pub plan: String,
    pub credits_cents: i64,
    pub metadata: ResourceMetadata,
}

/// Subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionRecord {
    pub id: SubscriptionId,
    pub billing_account_id: BillingAccountId,
    pub plan: String,
    pub active: bool,
    pub metadata: ResourceMetadata,
}

/// Invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoiceRecord {
    pub id: InvoiceId,
    pub billing_account_id: BillingAccountId,
    pub description: String,
    pub total_cents: i64,
    pub settled: bool,
    pub metadata: ResourceMetadata,
}

/// Budget window applied to tracked spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BudgetPeriod {
    #[default]
    Monthly,
    Quarterly,
    Annual,
    Custom,
}

/// Spend-cap policy applied when tracked burn reaches or exceeds budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SpendCapBehavior {
    #[default]
    Soft,
    Hard,
}

/// Durable budget resource bound to one billing account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetRecord {
    pub id: String,
    pub billing_account_id: BillingAccountId,
    pub name: String,
    pub period: BudgetPeriod,
    pub amount_cents: i64,
    pub threshold_percentages: Vec<u8>,
    pub cap_behavior: SpendCapBehavior,
    pub active: bool,
    pub metadata: ResourceMetadata,
}

/// One burn-tracking entry admitted against a budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetBurnRecord {
    pub id: String,
    pub budget_id: String,
    pub billing_account_id: BillingAccountId,
    pub source_kind: String,
    pub source_id: String,
    pub amount_cents: i64,
    pub resulting_burn_cents: i64,
    pub recorded_at: OffsetDateTime,
}

/// Notification kind emitted when spend crosses a budget boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetNotificationKind {
    ThresholdReached,
    SoftCapExceeded,
    HardCapBlocked,
}

impl BudgetNotificationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::ThresholdReached => "threshold_reached",
            Self::SoftCapExceeded => "soft_cap_exceeded",
            Self::HardCapBlocked => "hard_cap_blocked",
        }
    }
}

/// Durable threshold or cap notification emitted by billing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetNotificationRecord {
    pub id: String,
    pub budget_id: String,
    pub billing_account_id: BillingAccountId,
    pub kind: BudgetNotificationKind,
    pub threshold_percentage: Option<u8>,
    pub invoice_total_cents: i64,
    pub projected_burn_cents: i64,
    pub budget_amount_cents: i64,
    pub cap_behavior: SpendCapBehavior,
    pub message: String,
    pub created_at: OffsetDateTime,
}

/// Support tier anchored to billing plan state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportTier {
    Standard,
    Business,
    Enterprise,
    Custom,
}

impl SupportTier {
    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Business => "business",
            Self::Enterprise => "enterprise",
            Self::Custom => "custom",
        }
    }
}

/// Billing source that granted a support entitlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportEntitlementSourceKind {
    BillingAccount,
    Subscription,
}

impl SupportEntitlementSourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::BillingAccount => "billing_account",
            Self::Subscription => "subscription",
        }
    }
}

/// Durable support-entitlement record tied to billing plan anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportEntitlementRecord {
    pub id: String,
    pub billing_account_id: BillingAccountId,
    pub subscription_id: Option<SubscriptionId>,
    pub source_kind: SupportEntitlementSourceKind,
    pub source_plan: String,
    pub support_tier: SupportTier,
    pub channels: Vec<String>,
    pub initial_response_sla_minutes: u32,
    pub active: bool,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwnerBillingSummary {
    owner_id: String,
    account_count: usize,
    subscription_count: usize,
    invoice_count: usize,
    unsettled_invoice_total_cents: i64,
    budget_count: usize,
    budgeted_amount_cents: i64,
    tracked_burn_cents: i64,
    budget_notification_count: usize,
    budgets_at_or_over_cap: usize,
    support_entitlement_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwnerBillingSummaries {
    owners: Vec<OwnerBillingSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BillingSummary {
    account_count: usize,
    unique_owner_count: usize,
    account_owner_link_count: usize,
    owner_account_totals: BTreeMap<String, usize>,
    subscription_count: usize,
    active_subscription_count: usize,
    subscriptions_linked_to_active_accounts: usize,
    invoice_count: usize,
    settled_invoice_count: usize,
    unsettled_invoice_count: usize,
    settled_invoice_total_cents: i64,
    unsettled_invoice_total_cents: i64,
    invoices_linked_to_active_accounts: usize,
    invoice_status_totals: BTreeMap<String, usize>,
    provider_sync_task_count: usize,
    provider_sync_status_totals: BTreeMap<String, usize>,
    support_entitlement_count: usize,
    active_support_entitlement_count: usize,
    support_entitlements_linked_to_active_accounts: usize,
    support_entitlements_linked_to_active_subscriptions: usize,
    support_entitlement_source_totals: BTreeMap<String, usize>,
    support_tier_totals: BTreeMap<String, usize>,
    budget_count: usize,
    active_budget_count: usize,
    budgeted_amount_cents: i64,
    tracked_burn_cents: i64,
    budget_burn_record_count: usize,
    budget_notification_count: usize,
    budget_notification_kind_totals: BTreeMap<String, usize>,
    soft_cap_budget_count: usize,
    hard_cap_budget_count: usize,
    budgets_at_or_over_cap: usize,
}

/// Durable external provider sync task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderSyncTask {
    pub id: AuditId,
    pub provider: String,
    pub action: String,
    pub resource_id: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateAccountRequest {
    owner_id: String,
    plan: String,
    credits_cents: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateSubscriptionRequest {
    billing_account_id: String,
    plan: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateInvoiceRequest {
    billing_account_id: String,
    description: String,
    total_cents: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateBudgetRequest {
    billing_account_id: String,
    name: String,
    #[serde(default)]
    period: BudgetPeriod,
    amount_cents: i64,
    #[serde(default = "default_budget_threshold_percentages")]
    threshold_percentages: Vec<u8>,
    #[serde(default)]
    cap_behavior: SpendCapBehavior,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetSpendPlan {
    budget: BudgetRecord,
    projected_burn_cents: i64,
    notifications: Vec<BudgetNotificationDraft>,
    hard_cap_blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BudgetNotificationDraft {
    kind: BudgetNotificationKind,
    threshold_percentage: Option<u8>,
    invoice_total_cents: i64,
    projected_burn_cents: i64,
    message: String,
}

fn validate_non_empty(value_name: &'static str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(PlatformError::invalid(format!(
            "{value_name} may not be empty"
        )))
    } else {
        Ok(trimmed.to_owned())
    }
}

fn validate_non_negative_cents(value_name: &'static str, value: i64) -> Result<i64> {
    if value < 0 {
        Err(PlatformError::invalid(format!(
            "{value_name} must be greater than or equal to zero"
        )))
    } else {
        Ok(value)
    }
}

fn validate_positive_cents(value_name: &'static str, value: i64) -> Result<i64> {
    if value <= 0 {
        Err(PlatformError::invalid(format!(
            "{value_name} must be greater than zero"
        )))
    } else {
        Ok(value)
    }
}

fn default_budget_threshold_percentages() -> Vec<u8> {
    vec![50, 80, 100]
}

fn validate_budget_threshold_percentages(values: &[u8]) -> Result<Vec<u8>> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        if !(1..=100).contains(value) {
            return Err(PlatformError::invalid(
                "threshold_percentages values must be between 1 and 100",
            ));
        }
        if !seen.insert(*value) {
            return Err(PlatformError::invalid(
                "threshold_percentages must not contain duplicates",
            ));
        }
        normalized.push(*value);
    }
    normalized.sort_unstable();
    Ok(normalized)
}

fn generate_local_resource_id(prefix: &str) -> Result<String> {
    let id = AuditId::generate().map_err(|error| {
        PlatformError::unavailable("failed to allocate local billing resource id")
            .with_detail(error.to_string())
    })?;
    let (_, suffix) = id
        .as_str()
        .split_once('_')
        .ok_or_else(|| PlatformError::unavailable("generated audit id had unexpected shape"))?;
    Ok(format!("{prefix}_{suffix}"))
}

fn support_tier_for_plan(plan: &str) -> SupportTier {
    match plan {
        "starter" | "basic" | "developer" => SupportTier::Standard,
        "pro" | "business" | "team" => SupportTier::Business,
        "enterprise" | "enterprise_plus" => SupportTier::Enterprise,
        _ => SupportTier::Custom,
    }
}

fn support_channels_for_tier(tier: SupportTier) -> Vec<String> {
    match tier {
        SupportTier::Standard => vec![String::from("portal"), String::from("email")],
        SupportTier::Business => vec![
            String::from("portal"),
            String::from("email"),
            String::from("phone"),
        ],
        SupportTier::Enterprise => vec![
            String::from("portal"),
            String::from("email"),
            String::from("phone"),
            String::from("slack"),
        ],
        SupportTier::Custom => vec![String::from("portal"), String::from("email")],
    }
}

fn initial_response_sla_minutes_for_tier(tier: SupportTier) -> u32 {
    match tier {
        SupportTier::Standard => 1_440,
        SupportTier::Business => 240,
        SupportTier::Enterprise => 60,
        SupportTier::Custom => 1_440,
    }
}

fn active_values<T>(records: Vec<(String, uhost_store::StoredDocument<T>)>) -> Vec<T> {
    records
        .into_iter()
        .filter_map(|(_, record)| (!record.deleted).then_some(record.value))
        .collect()
}

/// Billing service.
#[derive(Debug, Clone)]
pub struct BillingService {
    accounts: DocumentStore<BillingAccount>,
    subscriptions: DocumentStore<SubscriptionRecord>,
    invoices: DocumentStore<InvoiceRecord>,
    support_entitlements: DocumentStore<SupportEntitlementRecord>,
    budgets: DocumentStore<BudgetRecord>,
    budget_burn: DocumentStore<BudgetBurnRecord>,
    budget_notifications: DocumentStore<BudgetNotificationRecord>,
    provider_sync: DocumentStore<ProviderSyncTask>,
    state_root: PathBuf,
}

impl BillingService {
    /// Open billing state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("billing");
        Ok(Self {
            accounts: DocumentStore::open(root.join("accounts.json")).await?,
            subscriptions: DocumentStore::open(root.join("subscriptions.json")).await?,
            invoices: DocumentStore::open(root.join("invoices.json")).await?,
            support_entitlements: DocumentStore::open(root.join("support_entitlements.json"))
                .await?,
            budgets: DocumentStore::open(root.join("budgets.json")).await?,
            budget_burn: DocumentStore::open(root.join("budget_burn.json")).await?,
            budget_notifications: DocumentStore::open(root.join("budget_notifications.json"))
                .await?,
            provider_sync: DocumentStore::open(root.join("provider_sync.json")).await?,
            state_root: root,
        })
    }

    async fn create_account(
        &self,
        request: CreateAccountRequest,
    ) -> Result<http::Response<ApiBody>> {
        let owner_id = validate_non_empty("owner_id", &request.owner_id)?;
        let plan = validate_slug(&request.plan)?;
        let credits_cents = validate_non_negative_cents("credits_cents", request.credits_cents)?;
        let id = BillingAccountId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate billing account id")
                .with_detail(error.to_string())
        })?;
        let record = BillingAccount {
            id: id.clone(),
            owner_id,
            plan,
            credits_cents,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let created = self.accounts.create(id.as_str(), record.clone()).await?;
        let provider_sync = match self
            .enqueue_stripe_task(
                "create_customer",
                id.as_str(),
                serde_json::json!({
                    "owner_id": record.owner_id,
                    "plan": record.plan,
                    "credits_cents": record.credits_cents,
                }),
            )
            .await
        {
            Ok(provider_sync) => provider_sync,
            Err(error) => {
                if let Err(rollback_error) = self
                    .accounts
                    .soft_delete(id.as_str(), Some(created.version))
                    .await
                {
                    return Err(PlatformError::unavailable(
                        "failed to enqueue provider sync task for billing account",
                    )
                    .with_detail(format!("{error}; rollback failed: {rollback_error}")));
                }
                return Err(error);
            }
        };
        if let Err(error) = self.provision_account_support_entitlement(&record).await {
            let _ = self
                .provider_sync
                .soft_delete(provider_sync.value.id.as_str(), Some(provider_sync.version))
                .await;
            let _ = self
                .accounts
                .soft_delete(id.as_str(), Some(created.version))
                .await;
            return Err(PlatformError::unavailable(
                "failed to persist support entitlement for billing account",
            )
            .with_detail(error.to_string()));
        }
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_subscription(
        &self,
        request: CreateSubscriptionRequest,
    ) -> Result<http::Response<ApiBody>> {
        let plan = validate_slug(&request.plan)?;
        let account_id = BillingAccountId::parse(request.billing_account_id).map_err(|error| {
            PlatformError::invalid("invalid billing_account_id").with_detail(error.to_string())
        })?;
        let account = self
            .accounts
            .get(account_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("billing account does not exist"))?;
        if account.deleted {
            return Err(PlatformError::not_found("billing account does not exist"));
        }
        let id = SubscriptionId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate subscription id")
                .with_detail(error.to_string())
        })?;
        let record = SubscriptionRecord {
            id: id.clone(),
            billing_account_id: account_id,
            plan,
            active: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let created = self
            .subscriptions
            .create(id.as_str(), record.clone())
            .await?;
        let provider_sync = match self
            .enqueue_stripe_task(
                "create_subscription",
                id.as_str(),
                serde_json::json!({
                    "billing_account_id": record.billing_account_id,
                    "plan": record.plan,
                }),
            )
            .await
        {
            Ok(provider_sync) => provider_sync,
            Err(error) => {
                if let Err(rollback_error) = self
                    .subscriptions
                    .soft_delete(id.as_str(), Some(created.version))
                    .await
                {
                    return Err(PlatformError::unavailable(
                        "failed to enqueue provider sync task for subscription",
                    )
                    .with_detail(format!("{error}; rollback failed: {rollback_error}")));
                }
                return Err(error);
            }
        };
        if let Err(error) = self
            .provision_subscription_support_entitlement(&record)
            .await
        {
            let _ = self
                .provider_sync
                .soft_delete(provider_sync.value.id.as_str(), Some(provider_sync.version))
                .await;
            let _ = self
                .subscriptions
                .soft_delete(id.as_str(), Some(created.version))
                .await;
            return Err(PlatformError::unavailable(
                "failed to persist support entitlement for subscription",
            )
            .with_detail(error.to_string()));
        }
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_budget(&self, request: CreateBudgetRequest) -> Result<http::Response<ApiBody>> {
        let account_id = BillingAccountId::parse(request.billing_account_id).map_err(|error| {
            PlatformError::invalid("invalid billing_account_id").with_detail(error.to_string())
        })?;
        let account = self
            .accounts
            .get(account_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("billing account does not exist"))?;
        if account.deleted {
            return Err(PlatformError::not_found("billing account does not exist"));
        }

        let name = validate_non_empty("name", &request.name)?;
        let amount_cents = validate_positive_cents("amount_cents", request.amount_cents)?;
        let threshold_percentages =
            validate_budget_threshold_percentages(&request.threshold_percentages)?;
        let id = generate_local_resource_id("bdg")?;
        let record = BudgetRecord {
            id: id.clone(),
            billing_account_id: account_id,
            name,
            period: request.period,
            amount_cents,
            threshold_percentages,
            cap_behavior: request.cap_behavior,
            active: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.clone()),
                sha256_hex(id.as_bytes()),
            ),
        };
        self.budgets.create(id.as_str(), record.clone()).await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_invoice(
        &self,
        request: CreateInvoiceRequest,
    ) -> Result<http::Response<ApiBody>> {
        let description = validate_non_empty("description", &request.description)?;
        let total_cents = validate_non_negative_cents("total_cents", request.total_cents)?;
        let account_id = BillingAccountId::parse(request.billing_account_id).map_err(|error| {
            PlatformError::invalid("invalid billing_account_id").with_detail(error.to_string())
        })?;
        let account = self
            .accounts
            .get(account_id.as_str())
            .await?
            .ok_or_else(|| PlatformError::not_found("billing account does not exist"))?;
        if account.deleted {
            return Err(PlatformError::not_found("billing account does not exist"));
        }
        let spend_plan = self
            .plan_budget_spend(account_id.clone(), total_cents)
            .await?;
        if spend_plan.iter().any(|plan| plan.hard_cap_blocked) {
            let notifications = spend_plan
                .iter()
                .filter(|plan| plan.hard_cap_blocked)
                .flat_map(|plan| {
                    plan.notifications
                        .iter()
                        .map(|draft| (plan.budget.clone(), draft))
                })
                .collect::<Vec<_>>();
            if let Err(error) = self.persist_budget_notifications(&notifications).await {
                return Err(PlatformError::unavailable(
                    "failed to persist hard-cap budget notification",
                )
                .with_detail(error.to_string()));
            }
            let blocked_budget_ids = spend_plan
                .iter()
                .filter(|plan| plan.hard_cap_blocked)
                .map(|plan| plan.budget.id.clone())
                .collect::<Vec<_>>();
            return Err(
                PlatformError::conflict("hard budget cap exceeded").with_detail(format!(
                    "blocked by budgets: {}",
                    blocked_budget_ids.join(", ")
                )),
            );
        }
        let id = InvoiceId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate invoice id")
                .with_detail(error.to_string())
        })?;
        let record = InvoiceRecord {
            id: id.clone(),
            billing_account_id: account_id,
            description,
            total_cents,
            settled: false,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        let created = self.invoices.create(id.as_str(), record.clone()).await?;
        let provider_sync = match self
            .enqueue_stripe_task(
                "create_invoice",
                id.as_str(),
                serde_json::json!({
                    "billing_account_id": record.billing_account_id,
                    "description": record.description,
                    "total_cents": record.total_cents,
                }),
            )
            .await
        {
            Ok(provider_sync) => provider_sync,
            Err(error) => {
                if let Err(rollback_error) = self
                    .invoices
                    .soft_delete(id.as_str(), Some(created.version))
                    .await
                {
                    return Err(PlatformError::unavailable(
                        "failed to enqueue provider sync task for invoice",
                    )
                    .with_detail(format!("{error}; rollback failed: {rollback_error}")));
                }
                return Err(error);
            }
        };

        if let Err(error) = self
            .persist_budget_effects_for_invoice(&record, &spend_plan)
            .await
        {
            let _ = self
                .provider_sync
                .soft_delete(provider_sync.value.id.as_str(), Some(provider_sync.version))
                .await;
            let _ = self
                .invoices
                .soft_delete(id.as_str(), Some(created.version))
                .await;
            return Err(PlatformError::unavailable(
                "failed to persist budget tracking for invoice",
            )
            .with_detail(error.to_string()));
        }
        json_response(StatusCode::CREATED, &record)
    }

    async fn enqueue_stripe_task(
        &self,
        action: &str,
        resource_id: &str,
        payload: serde_json::Value,
    ) -> Result<uhost_store::StoredDocument<ProviderSyncTask>> {
        let id = AuditId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate provider sync task id")
                .with_detail(error.to_string())
        })?;
        let task = ProviderSyncTask {
            id: id.clone(),
            provider: String::from("stripe"),
            action: String::from(action),
            resource_id: String::from(resource_id),
            payload,
            status: String::from("pending"),
            last_error: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        self.provider_sync.create(id.as_str(), task).await
    }

    async fn persist_support_entitlement(
        &self,
        billing_account_id: BillingAccountId,
        subscription_id: Option<SubscriptionId>,
        source_kind: SupportEntitlementSourceKind,
        source_plan: &str,
    ) -> Result<()> {
        let support_tier = support_tier_for_plan(source_plan);
        let channels = support_channels_for_tier(support_tier);
        let id = generate_local_resource_id("set")?;
        let record = SupportEntitlementRecord {
            id: id.clone(),
            billing_account_id,
            subscription_id,
            source_kind,
            source_plan: source_plan.to_owned(),
            support_tier,
            channels,
            initial_response_sla_minutes: initial_response_sla_minutes_for_tier(support_tier),
            active: true,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.clone()),
                sha256_hex(id.as_bytes()),
            ),
        };
        self.support_entitlements
            .create(id.as_str(), record)
            .await?;
        Ok(())
    }

    async fn provision_account_support_entitlement(&self, account: &BillingAccount) -> Result<()> {
        self.persist_support_entitlement(
            account.id.clone(),
            None,
            SupportEntitlementSourceKind::BillingAccount,
            &account.plan,
        )
        .await
    }

    async fn provision_subscription_support_entitlement(
        &self,
        subscription: &SubscriptionRecord,
    ) -> Result<()> {
        self.persist_support_entitlement(
            subscription.billing_account_id.clone(),
            Some(subscription.id.clone()),
            SupportEntitlementSourceKind::Subscription,
            &subscription.plan,
        )
        .await
    }

    async fn support_entitlement_records(&self) -> Result<Vec<SupportEntitlementRecord>> {
        Ok(active_values(self.support_entitlements.list().await?))
    }

    async fn active_support_entitlements(&self) -> Result<Vec<SupportEntitlementRecord>> {
        Ok(self
            .support_entitlement_records()
            .await?
            .into_iter()
            .filter(|record| record.active)
            .collect())
    }

    async fn active_budgets(&self) -> Result<Vec<BudgetRecord>> {
        Ok(active_values(self.budgets.list().await?)
            .into_iter()
            .filter(|budget| budget.active)
            .collect())
    }

    async fn active_budget_burn(&self) -> Result<Vec<BudgetBurnRecord>> {
        Ok(active_values(self.budget_burn.list().await?))
    }

    async fn active_budget_notifications(&self) -> Result<Vec<BudgetNotificationRecord>> {
        Ok(active_values(self.budget_notifications.list().await?))
    }

    async fn burn_totals_by_budget(&self) -> Result<BTreeMap<String, i64>> {
        let mut totals = BTreeMap::new();
        for burn in self.active_budget_burn().await? {
            let entry = totals.entry(burn.budget_id).or_insert(0_i64);
            *entry = entry.saturating_add(burn.amount_cents);
        }
        Ok(totals)
    }

    async fn plan_budget_spend(
        &self,
        billing_account_id: BillingAccountId,
        invoice_total_cents: i64,
    ) -> Result<Vec<BudgetSpendPlan>> {
        let burn_totals = self.burn_totals_by_budget().await?;
        let budgets = self
            .active_budgets()
            .await?
            .into_iter()
            .filter(|budget| budget.billing_account_id == billing_account_id)
            .collect::<Vec<_>>();
        let mut plans = Vec::with_capacity(budgets.len());

        for budget in budgets {
            let current_burn_cents = burn_totals.get(&budget.id).copied().unwrap_or_default();
            let projected_burn_cents = current_burn_cents.saturating_add(invoice_total_cents);
            let hard_cap_blocked = budget.cap_behavior == SpendCapBehavior::Hard
                && projected_burn_cents > budget.amount_cents;
            let mut notifications = Vec::new();

            if hard_cap_blocked {
                notifications.push(BudgetNotificationDraft {
                    kind: BudgetNotificationKind::HardCapBlocked,
                    threshold_percentage: None,
                    invoice_total_cents,
                    projected_burn_cents,
                    message: format!(
                        "hard spend cap blocked invoice admission for budget `{}`",
                        budget.name
                    ),
                });
            } else {
                for threshold_percentage in &budget.threshold_percentages {
                    let threshold_cents =
                        (budget.amount_cents * i64::from(*threshold_percentage)) / 100_i64;
                    if current_burn_cents < threshold_cents
                        && projected_burn_cents >= threshold_cents
                    {
                        notifications.push(BudgetNotificationDraft {
                            kind: BudgetNotificationKind::ThresholdReached,
                            threshold_percentage: Some(*threshold_percentage),
                            invoice_total_cents,
                            projected_burn_cents,
                            message: format!(
                                "budget `{}` crossed the {}% threshold",
                                budget.name, threshold_percentage
                            ),
                        });
                    }
                }

                if budget.cap_behavior == SpendCapBehavior::Soft
                    && current_burn_cents <= budget.amount_cents
                    && projected_burn_cents > budget.amount_cents
                {
                    notifications.push(BudgetNotificationDraft {
                        kind: BudgetNotificationKind::SoftCapExceeded,
                        threshold_percentage: None,
                        invoice_total_cents,
                        projected_burn_cents,
                        message: format!("soft spend cap exceeded for budget `{}`", budget.name),
                    });
                }
            }

            plans.push(BudgetSpendPlan {
                budget,
                projected_burn_cents,
                notifications,
                hard_cap_blocked,
            });
        }

        Ok(plans)
    }

    async fn persist_budget_notifications(
        &self,
        drafts: &[(BudgetRecord, &BudgetNotificationDraft)],
    ) -> Result<Vec<(String, u64)>> {
        let mut created = Vec::new();
        for (budget, draft) in drafts {
            let id = generate_local_resource_id("bnt")?;
            let record = BudgetNotificationRecord {
                id: id.clone(),
                budget_id: budget.id.clone(),
                billing_account_id: budget.billing_account_id.clone(),
                kind: draft.kind,
                threshold_percentage: draft.threshold_percentage,
                invoice_total_cents: draft.invoice_total_cents,
                projected_burn_cents: draft.projected_burn_cents,
                budget_amount_cents: budget.amount_cents,
                cap_behavior: budget.cap_behavior,
                message: draft.message.clone(),
                created_at: OffsetDateTime::now_utc(),
            };
            match self.budget_notifications.create(id.as_str(), record).await {
                Ok(stored) => created.push((id, stored.version)),
                Err(error) => {
                    for (id, version) in created.into_iter().rev() {
                        let _ = self
                            .budget_notifications
                            .soft_delete(id.as_str(), Some(version))
                            .await;
                    }
                    return Err(error);
                }
            }
        }
        Ok(created)
    }

    async fn persist_budget_effects_for_invoice(
        &self,
        invoice: &InvoiceRecord,
        spend_plan: &[BudgetSpendPlan],
    ) -> Result<()> {
        let mut created_burns = Vec::new();
        let notification_drafts = spend_plan
            .iter()
            .flat_map(|plan| {
                plan.notifications
                    .iter()
                    .map(|draft| (plan.budget.clone(), draft))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for plan in spend_plan {
            let burn_id = generate_local_resource_id("brn")?;
            let burn = BudgetBurnRecord {
                id: burn_id.clone(),
                budget_id: plan.budget.id.clone(),
                billing_account_id: invoice.billing_account_id.clone(),
                source_kind: String::from("invoice"),
                source_id: invoice.id.to_string(),
                amount_cents: invoice.total_cents,
                resulting_burn_cents: plan.projected_burn_cents,
                recorded_at: OffsetDateTime::now_utc(),
            };
            match self.budget_burn.create(burn_id.as_str(), burn).await {
                Ok(stored) => created_burns.push((burn_id, stored.version)),
                Err(error) => {
                    for (id, version) in created_burns.into_iter().rev() {
                        let _ = self
                            .budget_burn
                            .soft_delete(id.as_str(), Some(version))
                            .await;
                    }
                    return Err(error);
                }
            }
        }

        if let Err(error) = self
            .persist_budget_notifications(&notification_drafts)
            .await
        {
            for (id, version) in created_burns.into_iter().rev() {
                let _ = self
                    .budget_burn
                    .soft_delete(id.as_str(), Some(version))
                    .await;
            }
            return Err(error);
        }

        Ok(())
    }

    async fn owner_summaries(&self) -> Result<OwnerBillingSummaries> {
        let accounts = active_values(self.accounts.list().await?);
        let mut owner_summaries: BTreeMap<String, OwnerBillingSummary> = BTreeMap::new();
        let mut account_owner: BTreeMap<BillingAccountId, String> = BTreeMap::new();
        let burn_totals = self.burn_totals_by_budget().await?;

        for account in accounts {
            account_owner.insert(account.id.clone(), account.owner_id.clone());
            let summary = owner_summaries
                .entry(account.owner_id.clone())
                .or_insert_with(|| OwnerBillingSummary {
                    owner_id: account.owner_id.clone(),
                    account_count: 0,
                    subscription_count: 0,
                    invoice_count: 0,
                    unsettled_invoice_total_cents: 0,
                    budget_count: 0,
                    budgeted_amount_cents: 0,
                    tracked_burn_cents: 0,
                    budget_notification_count: 0,
                    budgets_at_or_over_cap: 0,
                    support_entitlement_count: 0,
                });
            summary.account_count += 1;
        }

        for subscription in active_values(self.subscriptions.list().await?) {
            if let Some(owner_id) = account_owner.get(&subscription.billing_account_id) {
                let summary = owner_summaries.entry(owner_id.clone()).or_insert_with(|| {
                    OwnerBillingSummary {
                        owner_id: owner_id.clone(),
                        account_count: 0,
                        subscription_count: 0,
                        invoice_count: 0,
                        unsettled_invoice_total_cents: 0,
                        budget_count: 0,
                        budgeted_amount_cents: 0,
                        tracked_burn_cents: 0,
                        budget_notification_count: 0,
                        budgets_at_or_over_cap: 0,
                        support_entitlement_count: 0,
                    }
                });
                summary.subscription_count += 1;
            }
        }

        for invoice in active_values(self.invoices.list().await?) {
            if let Some(owner_id) = account_owner.get(&invoice.billing_account_id) {
                let summary = owner_summaries.entry(owner_id.clone()).or_insert_with(|| {
                    OwnerBillingSummary {
                        owner_id: owner_id.clone(),
                        account_count: 0,
                        subscription_count: 0,
                        invoice_count: 0,
                        unsettled_invoice_total_cents: 0,
                        budget_count: 0,
                        budgeted_amount_cents: 0,
                        tracked_burn_cents: 0,
                        budget_notification_count: 0,
                        budgets_at_or_over_cap: 0,
                        support_entitlement_count: 0,
                    }
                });
                summary.invoice_count += 1;
                if !invoice.settled {
                    summary.unsettled_invoice_total_cents += invoice.total_cents;
                }
            }
        }

        for budget in self.active_budgets().await? {
            if let Some(owner_id) = account_owner.get(&budget.billing_account_id) {
                let summary = owner_summaries.entry(owner_id.clone()).or_insert_with(|| {
                    OwnerBillingSummary {
                        owner_id: owner_id.clone(),
                        account_count: 0,
                        subscription_count: 0,
                        invoice_count: 0,
                        unsettled_invoice_total_cents: 0,
                        budget_count: 0,
                        budgeted_amount_cents: 0,
                        tracked_burn_cents: 0,
                        budget_notification_count: 0,
                        budgets_at_or_over_cap: 0,
                        support_entitlement_count: 0,
                    }
                });
                summary.budget_count += 1;
                summary.budgeted_amount_cents += budget.amount_cents;
                let tracked_burn_cents = burn_totals.get(&budget.id).copied().unwrap_or_default();
                summary.tracked_burn_cents += tracked_burn_cents;
                if tracked_burn_cents >= budget.amount_cents {
                    summary.budgets_at_or_over_cap += 1;
                }
            }
        }

        for notification in self.active_budget_notifications().await? {
            if let Some(owner_id) = account_owner.get(&notification.billing_account_id) {
                let summary = owner_summaries.entry(owner_id.clone()).or_insert_with(|| {
                    OwnerBillingSummary {
                        owner_id: owner_id.clone(),
                        account_count: 0,
                        subscription_count: 0,
                        invoice_count: 0,
                        unsettled_invoice_total_cents: 0,
                        budget_count: 0,
                        budgeted_amount_cents: 0,
                        tracked_burn_cents: 0,
                        budget_notification_count: 0,
                        budgets_at_or_over_cap: 0,
                        support_entitlement_count: 0,
                    }
                });
                summary.budget_notification_count += 1;
            }
        }

        for entitlement in self.active_support_entitlements().await? {
            if let Some(owner_id) = account_owner.get(&entitlement.billing_account_id) {
                let summary = owner_summaries.entry(owner_id.clone()).or_insert_with(|| {
                    OwnerBillingSummary {
                        owner_id: owner_id.clone(),
                        account_count: 0,
                        subscription_count: 0,
                        invoice_count: 0,
                        unsettled_invoice_total_cents: 0,
                        budget_count: 0,
                        budgeted_amount_cents: 0,
                        tracked_burn_cents: 0,
                        budget_notification_count: 0,
                        budgets_at_or_over_cap: 0,
                        support_entitlement_count: 0,
                    }
                });
                summary.support_entitlement_count += 1;
            }
        }

        Ok(OwnerBillingSummaries {
            owners: owner_summaries.into_values().collect(),
        })
    }

    async fn summary(&self) -> Result<BillingSummary> {
        let accounts = active_values(self.accounts.list().await?);
        let subscriptions = active_values(self.subscriptions.list().await?);
        let invoices = active_values(self.invoices.list().await?);
        let support_entitlements = self.support_entitlement_records().await?;
        let budgets = self.active_budgets().await?;
        let budget_burn = self.active_budget_burn().await?;
        let budget_notifications = self.active_budget_notifications().await?;
        let provider_tasks = active_values(self.provider_sync.list().await?);

        let mut owner_account_totals = BTreeMap::new();
        let mut account_owner = BTreeMap::new();
        let mut active_subscription_ids = BTreeSet::new();
        for account in &accounts {
            account_owner.insert(account.id.clone(), account.owner_id.clone());
            let entry = owner_account_totals
                .entry(account.owner_id.clone())
                .or_insert(0);
            *entry += 1;
        }

        let mut subscriptions_linked_to_active_accounts = 0_usize;
        let mut active_subscription_count = 0_usize;
        for subscription in &subscriptions {
            if subscription.active {
                active_subscription_count += 1;
                active_subscription_ids.insert(subscription.id.clone());
            }
            if account_owner.contains_key(&subscription.billing_account_id) {
                subscriptions_linked_to_active_accounts += 1;
            }
        }

        let mut settled_invoice_count = 0_usize;
        let mut unsettled_invoice_count = 0_usize;
        let mut settled_invoice_total_cents = 0_i64;
        let mut unsettled_invoice_total_cents = 0_i64;
        let mut invoices_linked_to_active_accounts = 0_usize;
        let mut invoice_status_totals = BTreeMap::from([
            (String::from("settled"), 0_usize),
            (String::from("unsettled"), 0),
        ]);
        for invoice in &invoices {
            if account_owner.contains_key(&invoice.billing_account_id) {
                invoices_linked_to_active_accounts += 1;
            }
            if invoice.settled {
                settled_invoice_count += 1;
                settled_invoice_total_cents += invoice.total_cents;
                if let Some(total) = invoice_status_totals.get_mut("settled") {
                    *total += 1;
                }
            } else {
                unsettled_invoice_count += 1;
                unsettled_invoice_total_cents += invoice.total_cents;
                if let Some(total) = invoice_status_totals.get_mut("unsettled") {
                    *total += 1;
                }
            }
        }

        let mut provider_sync_status_totals = BTreeMap::new();
        for task in &provider_tasks {
            let entry = provider_sync_status_totals
                .entry(task.status.clone())
                .or_insert(0);
            *entry += 1;
        }

        let support_entitlement_count = support_entitlements.len();
        let active_support_entitlements = support_entitlements
            .iter()
            .filter(|record| record.active)
            .collect::<Vec<_>>();
        let active_support_entitlement_count = active_support_entitlements.len();
        let support_entitlements_linked_to_active_accounts = active_support_entitlements
            .iter()
            .filter(|record| account_owner.contains_key(&record.billing_account_id))
            .count();
        let support_entitlements_linked_to_active_subscriptions = active_support_entitlements
            .iter()
            .filter(|record| {
                account_owner.contains_key(&record.billing_account_id)
                    && record
                        .subscription_id
                        .as_ref()
                        .is_some_and(|subscription_id| {
                            active_subscription_ids.contains(subscription_id)
                        })
            })
            .count();
        let mut support_entitlement_source_totals = BTreeMap::new();
        let mut support_tier_totals = BTreeMap::new();
        for entitlement in &support_entitlements {
            let source_entry = support_entitlement_source_totals
                .entry(entitlement.source_kind.as_str().to_owned())
                .or_insert(0_usize);
            *source_entry += 1;
            let tier_entry = support_tier_totals
                .entry(entitlement.support_tier.as_str().to_owned())
                .or_insert(0_usize);
            *tier_entry += 1;
        }

        let budgets = budgets
            .into_iter()
            .filter(|budget| account_owner.contains_key(&budget.billing_account_id))
            .collect::<Vec<_>>();
        let linked_budget_ids = budgets
            .iter()
            .map(|budget| budget.id.clone())
            .collect::<BTreeSet<_>>();
        let budget_burn = budget_burn
            .into_iter()
            .filter(|burn| linked_budget_ids.contains(&burn.budget_id))
            .collect::<Vec<_>>();
        let budget_notifications = budget_notifications
            .into_iter()
            .filter(|notification| linked_budget_ids.contains(&notification.budget_id))
            .collect::<Vec<_>>();
        let mut burn_totals = BTreeMap::new();
        for burn in &budget_burn {
            let entry = burn_totals.entry(burn.budget_id.clone()).or_insert(0_i64);
            *entry = entry.saturating_add(burn.amount_cents);
        }

        let budgeted_amount_cents = budgets.iter().fold(0_i64, |total, budget| {
            total.saturating_add(budget.amount_cents)
        });
        let tracked_burn_cents = budget_burn
            .iter()
            .fold(0_i64, |total, burn| total.saturating_add(burn.amount_cents));
        let mut budget_notification_kind_totals = BTreeMap::new();
        for notification in &budget_notifications {
            let entry = budget_notification_kind_totals
                .entry(notification.kind.as_str().to_owned())
                .or_insert(0_usize);
            *entry += 1;
        }
        let soft_cap_budget_count = budgets
            .iter()
            .filter(|budget| budget.cap_behavior == SpendCapBehavior::Soft)
            .count();
        let hard_cap_budget_count = budgets
            .iter()
            .filter(|budget| budget.cap_behavior == SpendCapBehavior::Hard)
            .count();
        let budgets_at_or_over_cap = budgets
            .iter()
            .filter(|budget| {
                burn_totals.get(&budget.id).copied().unwrap_or_default() >= budget.amount_cents
            })
            .count();

        Ok(BillingSummary {
            account_count: accounts.len(),
            unique_owner_count: owner_account_totals.len(),
            account_owner_link_count: owner_account_totals.values().sum(),
            owner_account_totals,
            subscription_count: subscriptions.len(),
            active_subscription_count,
            subscriptions_linked_to_active_accounts,
            invoice_count: invoices.len(),
            settled_invoice_count,
            unsettled_invoice_count,
            settled_invoice_total_cents,
            unsettled_invoice_total_cents,
            invoices_linked_to_active_accounts,
            invoice_status_totals,
            provider_sync_task_count: provider_tasks.len(),
            provider_sync_status_totals,
            support_entitlement_count,
            active_support_entitlement_count,
            support_entitlements_linked_to_active_accounts,
            support_entitlements_linked_to_active_subscriptions,
            support_entitlement_source_totals,
            support_tier_totals,
            budget_count: budgets.len(),
            active_budget_count: budgets.len(),
            budgeted_amount_cents,
            tracked_burn_cents,
            budget_burn_record_count: budget_burn.len(),
            budget_notification_count: budget_notifications.len(),
            budget_notification_kind_totals,
            soft_cap_budget_count,
            hard_cap_budget_count,
            budgets_at_or_over_cap,
        })
    }

    async fn mark_provider_sync_delivered(&self, sync_id: &str) -> Result<http::Response<ApiBody>> {
        let stored = self
            .provider_sync
            .get(sync_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("provider sync task does not exist"))?;
        let mut record = stored.value;
        record.status = String::from("delivered");
        record.updated_at = OffsetDateTime::now_utc();
        record.last_error = None;
        self.provider_sync
            .upsert(sync_id, record.clone(), Some(stored.version))
            .await?;
        json_response(StatusCode::OK, &record)
    }
}

impl HttpService for BillingService {
    fn name(&self) -> &'static str {
        "billing"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/billing")];
        ROUTE_CLAIMS
    }

    fn handle<'a>(
        &'a self,
        request: Request<uhost_runtime::RequestBody>,
        _context: RequestContext,
    ) -> ResponseFuture<'a> {
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let segments = path_segments(&path);

            match (method, segments.as_slice()) {
                (Method::GET, ["billing"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["billing", "summary"]) => {
                    let summary = self.summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["billing", "accounts"]) => {
                    let values = active_values(self.accounts.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["billing", "accounts"]) => {
                    let body: CreateAccountRequest = parse_json(request).await?;
                    self.create_account(body).await.map(Some)
                }
                (Method::GET, ["billing", "support-entitlements"]) => {
                    let values = self.active_support_entitlements().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["billing", "budgets"]) => {
                    let values = self.active_budgets().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["billing", "budgets"]) => {
                    let body: CreateBudgetRequest = parse_json(request).await?;
                    self.create_budget(body).await.map(Some)
                }
                (Method::GET, ["billing", "budget-burn"]) => {
                    let values = self.active_budget_burn().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["billing", "budget-notifications"]) => {
                    let values = self.active_budget_notifications().await?;
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["billing", "subscriptions"]) => {
                    let values = active_values(self.subscriptions.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["billing", "subscriptions"]) => {
                    let body: CreateSubscriptionRequest = parse_json(request).await?;
                    self.create_subscription(body).await.map(Some)
                }
                (Method::GET, ["billing", "invoices"]) => {
                    let values = active_values(self.invoices.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::GET, ["billing", "owner-summaries"]) => {
                    let summary = self.owner_summaries().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::POST, ["billing", "invoices"]) => {
                    let body: CreateInvoiceRequest = parse_json(request).await?;
                    self.create_invoice(body).await.map(Some)
                }
                (Method::GET, ["billing", "provider-sync"]) => {
                    let values = active_values(self.provider_sync.list().await?);
                    json_response(StatusCode::OK, &values).map(Some)
                }
                (Method::POST, ["billing", "provider-sync", sync_id, "deliver"]) => {
                    self.mark_provider_sync_delivered(sync_id).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;
    use time::OffsetDateTime;

    use super::{
        BillingService, BillingSummary, BudgetNotificationKind, BudgetPeriod, BudgetRecord,
        CreateAccountRequest, CreateBudgetRequest, CreateInvoiceRequest, CreateSubscriptionRequest,
        InvoiceRecord, ProviderSyncTask, SpendCapBehavior, SubscriptionRecord,
        SupportEntitlementSourceKind, SupportTier, active_values,
    };
    use crate::BillingAccount;
    use http_body_util::BodyExt;
    use serde::de::DeserializeOwned;
    use uhost_api::ApiBody;
    use uhost_core::ErrorCode;
    use uhost_store::StoredDocument;
    use uhost_types::BillingAccountId;

    #[test]
    fn active_values_skips_soft_deleted_records() {
        let records = vec![
            (
                String::from("active"),
                StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: String::from("keep"),
                },
            ),
            (
                String::from("deleted"),
                StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: true,
                    value: String::from("drop"),
                },
            ),
        ];

        assert_eq!(active_values(records), vec![String::from("keep")]);
    }

    #[tokio::test]
    async fn create_account_rejects_invalid_input() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_account(CreateAccountRequest {
                owner_id: String::from("tenant-123"),
                plan: String::from("Starter"),
                credits_cents: 0,
            })
            .await
            .expect_err("invalid request should fail");
        assert_eq!(error.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn create_invoice_rejects_negative_total() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_invoice(CreateInvoiceRequest {
                billing_account_id: String::from("bill-unknown"),
                description: String::from("monthly subscription"),
                total_cents: -1,
            })
            .await
            .expect_err("negative totals should fail");
        assert_eq!(error.code, ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn create_account_rolls_back_if_provider_sync_write_fails() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let provider_sync_path = temp.path().join("billing").join("provider_sync.json");
        fs::remove_file(&provider_sync_path).unwrap_or_else(|error| panic!("{error}"));
        fs::create_dir(&provider_sync_path).unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_account(CreateAccountRequest {
                owner_id: String::from("tenant-123"),
                plan: String::from("starter"),
                credits_cents: 500,
            })
            .await
            .expect_err("provider sync write should fail");
        assert_eq!(error.code, ErrorCode::Unavailable);

        let accounts = service
            .accounts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            active_values(accounts).is_empty(),
            "failed account write should roll back"
        );
    }

    async fn read_json<T: DeserializeOwned>(response: http::Response<ApiBody>) -> T {
        let collected = response
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let bytes = collected.to_bytes();
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("{error}"))
    }

    async fn create_account_for_test(
        service: &BillingService,
        owner_id: &str,
        plan: &str,
        credits_cents: i64,
    ) -> BillingAccount {
        read_json::<BillingAccount>(
            service
                .create_account(CreateAccountRequest {
                    owner_id: owner_id.to_owned(),
                    plan: plan.to_owned(),
                    credits_cents,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
    }

    async fn create_budget_for_test(
        service: &BillingService,
        billing_account_id: &BillingAccountId,
        name: &str,
        amount_cents: i64,
        threshold_percentages: Vec<u8>,
        cap_behavior: SpendCapBehavior,
    ) -> BudgetRecord {
        read_json::<BudgetRecord>(
            service
                .create_budget(CreateBudgetRequest {
                    billing_account_id: billing_account_id.to_string(),
                    name: name.to_owned(),
                    period: BudgetPeriod::Monthly,
                    amount_cents,
                    threshold_percentages,
                    cap_behavior,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await
    }

    #[tokio::test]
    async fn owner_summaries_group_accounts_by_owner() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let owner_a = "tenant-alpha";
        let owner_b = "tenant-bravo";

        let account_a = create_account_for_test(&service, owner_a, "starter", 0).await;
        let _account_b = create_account_for_test(&service, owner_b, "pro", 100).await;
        let budget_a = create_budget_for_test(
            &service,
            &account_a.id,
            "owner-a-primary",
            300,
            vec![50, 100],
            SpendCapBehavior::Soft,
        )
        .await;

        service
            .create_subscription(CreateSubscriptionRequest {
                billing_account_id: account_a.id.to_string(),
                plan: String::from("starter"),
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .create_invoice(CreateInvoiceRequest {
                billing_account_id: account_a.id.to_string(),
                description: String::from("service A"),
                total_cents: 250,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .create_invoice(CreateInvoiceRequest {
                billing_account_id: account_a.id.to_string(),
                description: String::from("settled A"),
                total_cents: 100,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .owner_summaries()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary.owners.len(), 2);
        let owner_a_summary = summary
            .owners
            .iter()
            .find(|entry| entry.owner_id == owner_a)
            .unwrap_or_else(|| panic!("missing owner_a summary"));
        assert_eq!(owner_a_summary.account_count, 1);
        assert_eq!(owner_a_summary.subscription_count, 1);
        assert_eq!(owner_a_summary.invoice_count, 2);
        assert_eq!(owner_a_summary.unsettled_invoice_total_cents, 350);
        assert_eq!(owner_a_summary.budget_count, 1);
        assert_eq!(owner_a_summary.budgeted_amount_cents, budget_a.amount_cents);
        assert_eq!(owner_a_summary.tracked_burn_cents, 350);
        assert_eq!(owner_a_summary.budget_notification_count, 3);
        assert_eq!(owner_a_summary.budgets_at_or_over_cap, 1);
        assert_eq!(owner_a_summary.support_entitlement_count, 2);

        let owner_b_summary = summary
            .owners
            .iter()
            .find(|entry| entry.owner_id == owner_b)
            .unwrap_or_else(|| panic!("missing owner_b summary"));
        assert_eq!(owner_b_summary.account_count, 1);
        assert_eq!(owner_b_summary.subscription_count, 0);
        assert_eq!(owner_b_summary.invoice_count, 0);
        assert_eq!(owner_b_summary.unsettled_invoice_total_cents, 0);
        assert_eq!(owner_b_summary.budget_count, 0);
        assert_eq!(owner_b_summary.budgeted_amount_cents, 0);
        assert_eq!(owner_b_summary.tracked_burn_cents, 0);
        assert_eq!(owner_b_summary.budget_notification_count, 0);
        assert_eq!(owner_b_summary.budgets_at_or_over_cap, 0);
        assert_eq!(owner_b_summary.support_entitlement_count, 1);
    }

    #[tokio::test]
    async fn account_and_subscription_creation_provision_support_entitlements() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let account = create_account_for_test(&service, "tenant-entitled", "starter", 0).await;
        let subscription = read_json::<SubscriptionRecord>(
            service
                .create_subscription(CreateSubscriptionRequest {
                    billing_account_id: account.id.to_string(),
                    plan: String::from("enterprise"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let entitlements = service
            .active_support_entitlements()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(entitlements.len(), 2);

        let account_entitlement = entitlements
            .iter()
            .find(|record| record.source_kind == SupportEntitlementSourceKind::BillingAccount)
            .unwrap_or_else(|| panic!("missing account entitlement"));
        assert_eq!(account_entitlement.billing_account_id, account.id);
        assert_eq!(account_entitlement.subscription_id, None);
        assert_eq!(account_entitlement.source_plan, "starter");
        assert_eq!(account_entitlement.support_tier, SupportTier::Standard);
        assert_eq!(
            account_entitlement.channels,
            vec![String::from("portal"), String::from("email")]
        );
        assert_eq!(account_entitlement.initial_response_sla_minutes, 1_440);

        let subscription_entitlement = entitlements
            .iter()
            .find(|record| record.subscription_id.as_ref() == Some(&subscription.id))
            .unwrap_or_else(|| panic!("missing subscription entitlement"));
        assert_eq!(
            subscription_entitlement.source_kind,
            SupportEntitlementSourceKind::Subscription
        );
        assert_eq!(subscription_entitlement.source_plan, "enterprise");
        assert_eq!(
            subscription_entitlement.support_tier,
            SupportTier::Enterprise
        );
        assert_eq!(
            subscription_entitlement.channels,
            vec![
                String::from("portal"),
                String::from("email"),
                String::from("phone"),
                String::from("slack"),
            ]
        );
        assert_eq!(subscription_entitlement.initial_response_sla_minutes, 60);
    }

    #[tokio::test]
    async fn create_account_rolls_back_if_support_entitlement_write_fails() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let entitlement_path = temp
            .path()
            .join("billing")
            .join("support_entitlements.json");
        fs::remove_file(&entitlement_path).unwrap_or_else(|error| panic!("{error}"));
        fs::create_dir(&entitlement_path).unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_account(CreateAccountRequest {
                owner_id: String::from("tenant-entitlement-fail"),
                plan: String::from("starter"),
                credits_cents: 500,
            })
            .await
            .expect_err("support entitlement write should fail");
        assert_eq!(error.code, ErrorCode::Unavailable);

        let accounts = service
            .accounts
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            active_values(accounts).is_empty(),
            "failed support entitlement write should roll back account"
        );

        let provider_sync = service
            .provider_sync
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            active_values(provider_sync).is_empty(),
            "failed support entitlement write should roll back provider sync"
        );
    }

    #[tokio::test]
    async fn soft_cap_budgets_track_burn_and_emit_threshold_notifications() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let account = create_account_for_test(&service, "tenant-soft", "starter", 0).await;
        let budget = create_budget_for_test(
            &service,
            &account.id,
            "monthly-soft",
            1_000,
            vec![50, 90, 100],
            SpendCapBehavior::Soft,
        )
        .await;

        let first_invoice = read_json::<InvoiceRecord>(
            service
                .create_invoice(CreateInvoiceRequest {
                    billing_account_id: account.id.to_string(),
                    description: String::from("first"),
                    total_cents: 600,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let second_invoice = read_json::<InvoiceRecord>(
            service
                .create_invoice(CreateInvoiceRequest {
                    billing_account_id: account.id.to_string(),
                    description: String::from("second"),
                    total_cents: 500,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let burn = service
            .active_budget_burn()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(burn.len(), 2);
        let first_burn = burn
            .iter()
            .find(|entry| entry.source_id == first_invoice.id.to_string())
            .unwrap_or_else(|| panic!("missing first burn"));
        assert_eq!(first_burn.budget_id, budget.id);
        assert_eq!(first_burn.resulting_burn_cents, 600);
        let second_burn = burn
            .iter()
            .find(|entry| entry.source_id == second_invoice.id.to_string())
            .unwrap_or_else(|| panic!("missing second burn"));
        assert_eq!(second_burn.resulting_burn_cents, 1_100);

        let notifications = service
            .active_budget_notifications()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(notifications.len(), 4);
        let thresholds = notifications
            .iter()
            .filter(|entry| entry.kind == BudgetNotificationKind::ThresholdReached)
            .map(|entry| entry.threshold_percentage.unwrap_or_default())
            .collect::<Vec<_>>();
        let mut thresholds = thresholds;
        thresholds.sort_unstable();
        assert_eq!(thresholds, vec![50, 90, 100]);
        assert!(
            notifications
                .iter()
                .any(|entry| entry.kind == BudgetNotificationKind::SoftCapExceeded)
        );
    }

    #[tokio::test]
    async fn hard_cap_budgets_block_invoice_creation() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let account = create_account_for_test(&service, "tenant-hard", "pro", 0).await;
        let budget = create_budget_for_test(
            &service,
            &account.id,
            "monthly-hard",
            500,
            vec![80, 100],
            SpendCapBehavior::Hard,
        )
        .await;

        service
            .create_invoice(CreateInvoiceRequest {
                billing_account_id: account.id.to_string(),
                description: String::from("within-cap"),
                total_cents: 400,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_invoice(CreateInvoiceRequest {
                billing_account_id: account.id.to_string(),
                description: String::from("blocked"),
                total_cents: 200,
            })
            .await
            .expect_err("hard cap should block invoice creation");
        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(
            error
                .detail
                .unwrap_or_default()
                .contains(budget.id.as_str())
        );

        let invoices = active_values(
            service
                .invoices
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert_eq!(invoices.len(), 1);

        let burn = service
            .active_budget_burn()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(burn.len(), 1);
        assert_eq!(burn[0].resulting_burn_cents, 400);

        let notifications = service
            .active_budget_notifications()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            notifications
                .iter()
                .any(|entry| entry.kind == BudgetNotificationKind::HardCapBlocked)
        );
    }

    #[tokio::test]
    async fn hard_cap_rejections_fail_closed_if_notification_write_fails() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let account = create_account_for_test(&service, "tenant-hard-fail", "pro", 0).await;
        let budget = create_budget_for_test(
            &service,
            &account.id,
            "monthly-hard-fail",
            500,
            vec![100],
            SpendCapBehavior::Hard,
        )
        .await;

        service
            .create_invoice(CreateInvoiceRequest {
                billing_account_id: account.id.to_string(),
                description: String::from("within-cap"),
                total_cents: 400,
            })
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let notifications_path = temp
            .path()
            .join("billing")
            .join("budget_notifications.json");
        fs::remove_file(&notifications_path).unwrap_or_else(|error| panic!("{error}"));
        fs::create_dir(&notifications_path).unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .create_invoice(CreateInvoiceRequest {
                billing_account_id: account.id.to_string(),
                description: String::from("blocked"),
                total_cents: 200,
            })
            .await
            .expect_err("hard cap should fail closed when notification persistence fails");
        assert_eq!(error.code, ErrorCode::Unavailable);

        let invoices = active_values(
            service
                .invoices
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        assert_eq!(invoices.len(), 1);

        let burn = service
            .active_budget_burn()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(burn.len(), 1);
        assert_eq!(burn[0].budget_id, budget.id);
        assert_eq!(burn[0].resulting_burn_cents, 400);
    }

    #[tokio::test]
    async fn summary_reflects_persisted_billing_records() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = BillingService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let owner_a = "tenant-alpha";
        let owner_b = "tenant-bravo";

        let account_a = read_json::<BillingAccount>(
            service
                .create_account(CreateAccountRequest {
                    owner_id: owner_a.to_string(),
                    plan: String::from("starter"),
                    credits_cents: 10,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let account_b = read_json::<BillingAccount>(
            service
                .create_account(CreateAccountRequest {
                    owner_id: owner_b.to_string(),
                    plan: String::from("pro"),
                    credits_cents: 20,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let budget_a = create_budget_for_test(
            &service,
            &account_a.id,
            "summary-budget",
            300,
            vec![50, 100],
            SpendCapBehavior::Soft,
        )
        .await;

        let _subscription_a = read_json::<SubscriptionRecord>(
            service
                .create_subscription(CreateSubscriptionRequest {
                    billing_account_id: account_a.id.to_string(),
                    plan: String::from("starter"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let subscription_b = read_json::<SubscriptionRecord>(
            service
                .create_subscription(CreateSubscriptionRequest {
                    billing_account_id: account_b.id.to_string(),
                    plan: String::from("pro"),
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let invoice_a = read_json::<InvoiceRecord>(
            service
                .create_invoice(CreateInvoiceRequest {
                    billing_account_id: account_a.id.to_string(),
                    description: String::from("a-unsettled"),
                    total_cents: 200,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;
        let invoice_b = read_json::<InvoiceRecord>(
            service
                .create_invoice(CreateInvoiceRequest {
                    billing_account_id: account_b.id.to_string(),
                    description: String::from("b-invoice"),
                    total_cents: 100,
                })
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let stored_subscription_b = service
            .subscriptions
            .get(subscription_b.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing subscription B"));
        let mut subscription_b_record = stored_subscription_b.value;
        subscription_b_record.active = false;
        service
            .subscriptions
            .upsert(
                subscription_b.id.as_str(),
                subscription_b_record,
                Some(stored_subscription_b.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored_invoice_b = service
            .invoices
            .get(invoice_b.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing invoice B"));
        let mut invoice_b_record = stored_invoice_b.value;
        invoice_b_record.settled = true;
        service
            .invoices
            .upsert(
                invoice_b.id.as_str(),
                invoice_b_record,
                Some(stored_invoice_b.version),
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .accounts
            .soft_delete(account_b.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let provider_sync_tasks = active_values(
            service
                .provider_sync
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let delivered_task_id = provider_sync_tasks
            .first()
            .map(|task| task.id.to_string())
            .unwrap_or_else(|| panic!("missing provider sync task"));
        let _delivered = read_json::<ProviderSyncTask>(
            service
                .mark_provider_sync_delivered(&delivered_task_id)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .await;

        let summary: BillingSummary = service
            .summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary.account_count, 1);
        assert_eq!(summary.unique_owner_count, 1);
        assert_eq!(summary.account_owner_link_count, 1);
        assert_eq!(summary.owner_account_totals.get(owner_a), Some(&1));
        assert_eq!(summary.owner_account_totals.get(owner_b), None);

        assert_eq!(summary.subscription_count, 2);
        assert_eq!(summary.active_subscription_count, 1);
        assert_eq!(summary.subscriptions_linked_to_active_accounts, 1);

        assert_eq!(summary.invoice_count, 2);
        assert_eq!(summary.settled_invoice_count, 1);
        assert_eq!(summary.unsettled_invoice_count, 1);
        assert_eq!(summary.settled_invoice_total_cents, 100);
        assert_eq!(summary.unsettled_invoice_total_cents, invoice_a.total_cents);
        assert_eq!(summary.invoices_linked_to_active_accounts, 1);
        assert_eq!(summary.invoice_status_totals.get("settled"), Some(&1));
        assert_eq!(summary.invoice_status_totals.get("unsettled"), Some(&1));

        assert_eq!(summary.provider_sync_task_count, 6);
        assert_eq!(
            summary.provider_sync_status_totals.get("delivered"),
            Some(&1)
        );
        assert_eq!(summary.provider_sync_status_totals.get("pending"), Some(&5));

        assert_eq!(summary.support_entitlement_count, 4);
        assert_eq!(summary.active_support_entitlement_count, 4);
        assert_eq!(summary.support_entitlements_linked_to_active_accounts, 2);
        assert_eq!(
            summary.support_entitlements_linked_to_active_subscriptions,
            1
        );
        assert_eq!(
            summary
                .support_entitlement_source_totals
                .get(SupportEntitlementSourceKind::BillingAccount.as_str()),
            Some(&2)
        );
        assert_eq!(
            summary
                .support_entitlement_source_totals
                .get(SupportEntitlementSourceKind::Subscription.as_str()),
            Some(&2)
        );
        assert_eq!(
            summary
                .support_tier_totals
                .get(SupportTier::Standard.as_str()),
            Some(&2)
        );
        assert_eq!(
            summary
                .support_tier_totals
                .get(SupportTier::Business.as_str()),
            Some(&2)
        );

        assert_eq!(summary.budget_count, 1);
        assert_eq!(summary.active_budget_count, 1);
        assert_eq!(summary.budgeted_amount_cents, budget_a.amount_cents);
        assert_eq!(summary.tracked_burn_cents, invoice_a.total_cents);
        assert_eq!(summary.budget_burn_record_count, 1);
        assert_eq!(summary.budget_notification_count, 1);
        assert_eq!(
            summary
                .budget_notification_kind_totals
                .get(BudgetNotificationKind::ThresholdReached.as_str()),
            Some(&1)
        );
        assert_eq!(summary.soft_cap_budget_count, 1);
        assert_eq!(summary.hard_cap_budget_count, 0);
        assert_eq!(summary.budgets_at_or_over_cap, 0);
    }
}
