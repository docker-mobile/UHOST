//! Tenant hierarchy service.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex, validate_slug};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{AuditLog, DocumentStore, StoredDocument};
use uhost_types::{
    AuditActor, AuditId, BillingAccountId, EnvironmentId, EventHeader, EventPayload,
    OrganizationId, OwnershipScope, PlatformEvent, ProjectId, ResourceMetadata, ServiceEvent,
};

/// Organization record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    pub id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub metadata: ResourceMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_account_id: Option<BillingAccountId>,
}

/// Project record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub organization_id: OrganizationId,
    pub name: String,
    pub slug: String,
    pub metadata: ResourceMetadata,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_account_id: Option<BillingAccountId>,
}

/// Environment record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    pub id: EnvironmentId,
    pub project_id: ProjectId,
    pub name: String,
    pub slug: String,
    pub region: String,
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateOrganizationRequest {
    name: String,
    slug: String,
    #[serde(default)]
    billing_account_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateProjectRequest {
    organization_id: String,
    name: String,
    slug: String,
    #[serde(default)]
    billing_account_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateEnvironmentRequest {
    project_id: String,
    name: String,
    slug: String,
    region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenancySummaryResponse {
    pub total_organizations: usize,
    pub total_projects: usize,
    pub total_environments: usize,
    pub organizations_with_billing_account: usize,
    pub projects_with_billing_account: usize,
    pub billing_linked_organizations: usize,
    pub billing_linked_projects: usize,
}

/// Tenancy service.
#[derive(Debug, Clone)]
pub struct TenancyService {
    organizations: DocumentStore<Organization>,
    projects: DocumentStore<Project>,
    environments: DocumentStore<Environment>,
    audit_log: AuditLog,
    state_root: PathBuf,
}

impl TenancyService {
    /// Open the tenancy service state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("tenancy");
        Ok(Self {
            organizations: DocumentStore::open(root.join("organizations.json")).await?,
            projects: DocumentStore::open(root.join("projects.json")).await?,
            environments: DocumentStore::open(root.join("environments.json")).await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            state_root: root,
        })
    }

    async fn create_organization(
        &self,
        request: CreateOrganizationRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let name = normalize_name(&request.name, "name")?;
        let slug = normalize_slug(&request.slug)?;
        if self
            .organizations
            .list()
            .await?
            .into_iter()
            .any(|(_, stored)| !stored.deleted && stored.value.slug == slug)
        {
            return Err(PlatformError::conflict("organization slug already exists"));
        }
        let billing_account_id = parse_optional_billing_account_id(request.billing_account_id)?;
        let id = OrganizationId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate organization id")
                .with_detail(error.to_string())
        })?;
        let organization = Organization {
            id: id.clone(),
            name,
            slug,
            billing_account_id,
            metadata: ResourceMetadata::new(
                OwnershipScope::Tenant,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.organizations
            .create(id.as_str(), organization.clone())
            .await?;
        self.append_event(
            "tenancy.organization.created.v1",
            "organization",
            id.as_str(),
            serde_json::json!({ "slug": organization.slug }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &organization)
    }

    async fn create_project(
        &self,
        request: CreateProjectRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let organization_id = OrganizationId::parse(request.organization_id.trim().to_owned())
            .map_err(|error| {
                PlatformError::invalid("invalid organization_id").with_detail(error.to_string())
            })?;
        let organization = self
            .organizations
            .get(organization_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("organization does not exist"))?;
        let name = normalize_name(&request.name, "name")?;
        let slug = normalize_slug(&request.slug)?;
        if self.projects.list().await?.into_iter().any(|(_, stored)| {
            !stored.deleted
                && stored.value.organization_id == organization.value.id
                && stored.value.slug == slug
        }) {
            return Err(PlatformError::conflict("project slug already exists"));
        }
        let billing_account_id = parse_optional_billing_account_id(request.billing_account_id)?;
        let id = ProjectId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate project id")
                .with_detail(error.to_string())
        })?;
        let project = Project {
            id: id.clone(),
            organization_id,
            name,
            slug,
            billing_account_id,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.projects.create(id.as_str(), project.clone()).await?;
        self.append_event(
            "tenancy.project.created.v1",
            "project",
            id.as_str(),
            serde_json::json!({ "organization_id": project.organization_id }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &project)
    }

    async fn create_environment(
        &self,
        request: CreateEnvironmentRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let project_id =
            ProjectId::parse(request.project_id.trim().to_owned()).map_err(|error| {
                PlatformError::invalid("invalid project_id").with_detail(error.to_string())
            })?;
        let project = self
            .projects
            .get(project_id.as_str())
            .await?
            .filter(|stored| !stored.deleted)
            .ok_or_else(|| PlatformError::not_found("project does not exist"))?;
        let name = normalize_name(&request.name, "name")?;
        let slug = normalize_slug(&request.slug)?;
        let region = normalize_region(&request.region)?;
        if self
            .environments
            .list()
            .await?
            .into_iter()
            .any(|(_, stored)| {
                !stored.deleted
                    && stored.value.project_id == project.value.id
                    && stored.value.slug == slug
            })
        {
            return Err(PlatformError::conflict("environment slug already exists"));
        }
        let id = EnvironmentId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate environment id")
                .with_detail(error.to_string())
        })?;
        let environment = Environment {
            id: id.clone(),
            project_id,
            name,
            slug,
            region,
            metadata: ResourceMetadata::new(
                OwnershipScope::Project,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.environments
            .create(id.as_str(), environment.clone())
            .await?;
        self.append_event(
            "tenancy.environment.created.v1",
            "environment",
            id.as_str(),
            serde_json::json!({ "project_id": environment.project_id, "region": environment.region }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &environment)
    }

    async fn tenancy_summary(&self) -> Result<TenancySummaryResponse> {
        let organizations = active_values(self.organizations.list().await?);
        let projects = active_values(self.projects.list().await?);
        let environments = active_values(self.environments.list().await?);

        let organizations_with_billing_account = organizations
            .iter()
            .filter(|organization| organization.billing_account_id.is_some())
            .count();
        let projects_with_billing_account = projects
            .iter()
            .filter(|project| project.billing_account_id.is_some())
            .count();

        let links = self.list_billing_links().await?;
        let billing_linked_organizations = links.organizations.len();
        let billing_linked_projects = links
            .organizations
            .iter()
            .map(|organization| organization.projects.len())
            .sum();

        Ok(TenancySummaryResponse {
            total_organizations: organizations.len(),
            total_projects: projects.len(),
            total_environments: environments.len(),
            organizations_with_billing_account,
            projects_with_billing_account,
            billing_linked_organizations,
            billing_linked_projects,
        })
    }

    async fn list_billing_links(&self) -> Result<BillingLinksResponse> {
        let mut organizations = active_values(self.organizations.list().await?);
        let mut projects = active_values(self.projects.list().await?);

        organizations.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        projects.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));

        let mut project_map: HashMap<OrganizationId, Vec<Project>> = HashMap::new();
        for project in projects {
            project_map
                .entry(project.organization_id.clone())
                .or_default()
                .push(project);
        }

        let organization_links = organizations
            .into_iter()
            .map(|organization| {
                let project_links = project_map
                    .remove(&organization.id)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|project| ProjectBillingLink {
                        project_id: project.id,
                        name: project.name,
                        slug: project.slug,
                        billing_account_id: project.billing_account_id,
                    })
                    .collect();
                OrganizationBillingLink {
                    organization_id: organization.id,
                    name: organization.name,
                    slug: organization.slug,
                    billing_account_id: organization.billing_account_id,
                    projects: project_links,
                }
            })
            .collect();

        Ok(BillingLinksResponse {
            organizations: organization_links,
        })
    }

    async fn append_event(
        &self,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        details: serde_json::Value,
        context: &RequestContext,
    ) -> Result<()> {
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("tenancy"),
                emitted_at: OffsetDateTime::now_utc(),
                actor: AuditActor {
                    subject: context
                        .actor
                        .clone()
                        .unwrap_or_else(|| String::from("system")),
                    actor_type: String::from("principal"),
                    source_ip: None,
                    correlation_id: context.correlation_id.clone(),
                },
            },
            payload: EventPayload::Service(ServiceEvent {
                resource_kind: resource_kind.to_owned(),
                resource_id: resource_id.to_owned(),
                action: String::from("created"),
                details,
            }),
        };
        self.audit_log.append(&event).await
    }
}

impl HttpService for TenancyService {
    fn name(&self) -> &'static str {
        "tenancy"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] =
            &[uhost_runtime::RouteClaim::prefix("/tenancy")];
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
                (Method::GET, ["tenancy"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["tenancy", "summary"]) => {
                    let summary = self.tenancy_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::GET, ["tenancy", "billing-links"]) => {
                    let response = self.list_billing_links().await?;
                    json_response(StatusCode::OK, &response).map(Some)
                }
                (Method::GET, ["tenancy", "organizations"]) => {
                    let records = active_values(self.organizations.list().await?);
                    json_response(StatusCode::OK, &records).map(Some)
                }
                (Method::POST, ["tenancy", "organizations"]) => {
                    let body: CreateOrganizationRequest = parse_json(request).await?;
                    self.create_organization(body, &context).await.map(Some)
                }
                (Method::GET, ["tenancy", "projects"]) => {
                    let records = active_values(self.projects.list().await?);
                    json_response(StatusCode::OK, &records).map(Some)
                }
                (Method::POST, ["tenancy", "projects"]) => {
                    let body: CreateProjectRequest = parse_json(request).await?;
                    self.create_project(body, &context).await.map(Some)
                }
                (Method::GET, ["tenancy", "environments"]) => {
                    let records = active_values(self.environments.list().await?);
                    json_response(StatusCode::OK, &records).map(Some)
                }
                (Method::POST, ["tenancy", "environments"]) => {
                    let body: CreateEnvironmentRequest = parse_json(request).await?;
                    self.create_environment(body, &context).await.map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_name(value: &str, field: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        Err(PlatformError::invalid(format!("{field} may not be empty")))
    } else {
        Ok(normalized.to_owned())
    }
}

fn normalize_slug(value: &str) -> Result<String> {
    validate_slug(value.trim())
}

fn normalize_region(value: &str) -> Result<String> {
    let region = value.trim().to_ascii_lowercase();
    if region.is_empty() {
        return Err(PlatformError::invalid("region may not be empty"));
    }
    validate_slug(&region)
}

fn parse_optional_billing_account_id(value: Option<String>) -> Result<Option<BillingAccountId>> {
    match value {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            BillingAccountId::parse(trimmed.to_owned())
                .map(Some)
                .map_err(|error| {
                    PlatformError::invalid("invalid billing_account_id")
                        .with_detail(error.to_string())
                })
        }
        None => Ok(None),
    }
}

fn active_values<T: Clone>(mut records: Vec<(String, StoredDocument<T>)>) -> Vec<T> {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    records
        .into_iter()
        .filter_map(|(_, stored)| (!stored.deleted).then_some(stored.value))
        .collect()
}

#[derive(Debug, Serialize)]
struct BillingLinksResponse {
    organizations: Vec<OrganizationBillingLink>,
}

#[derive(Debug, Serialize)]
struct OrganizationBillingLink {
    organization_id: OrganizationId,
    name: String,
    slug: String,
    billing_account_id: Option<BillingAccountId>,
    projects: Vec<ProjectBillingLink>,
}

#[derive(Debug, Serialize)]
struct ProjectBillingLink {
    project_id: ProjectId,
    name: String,
    slug: String,
    billing_account_id: Option<BillingAccountId>,
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use tempfile::tempdir;

    use super::{
        CreateEnvironmentRequest, CreateOrganizationRequest, CreateProjectRequest, Organization,
        TenancyService, active_values,
    };
    use time::OffsetDateTime;
    use uhost_core::RequestContext;
    use uhost_store::StoredDocument;
    use uhost_types::{BillingAccountId, OrganizationId, OwnershipScope, ResourceMetadata};

    #[tokio::test]
    async fn create_organization_writes_store() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = TenancyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let response = service
            .create_organization(
                CreateOrganizationRequest {
                    name: String::from("Example Org"),
                    slug: String::from("example-org"),
                    billing_account_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn create_organization_records_billing_account() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = TenancyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        let billing_id = BillingAccountId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .create_organization(
                CreateOrganizationRequest {
                    name: String::from("Example Org"),
                    slug: String::from("example-org"),
                    billing_account_id: Some(billing_id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let organization = service
            .organizations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        assert_eq!(organization.billing_account_id.as_ref(), Some(&billing_id));
    }

    #[tokio::test]
    async fn billing_links_return_attached_accounts() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = TenancyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let organization_billing =
            BillingAccountId::generate().unwrap_or_else(|error| panic!("{error}"));
        let project_billing =
            BillingAccountId::generate().unwrap_or_else(|error| panic!("{error}"));

        service
            .create_organization(
                CreateOrganizationRequest {
                    name: String::from("Example Org"),
                    slug: String::from("example-org"),
                    billing_account_id: Some(organization_billing.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .create_project(
                CreateProjectRequest {
                    organization_id: service
                        .organizations
                        .list()
                        .await
                        .unwrap_or_else(|error| panic!("{error}"))[0]
                        .1
                        .value
                        .id
                        .to_string(),
                    name: String::from("Core Platform"),
                    slug: String::from("core-platform"),
                    billing_account_id: Some(project_billing.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let links = service
            .list_billing_links()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(links.organizations.len(), 1);
        let organization = &links.organizations[0];
        assert_eq!(
            organization.billing_account_id.as_ref(),
            Some(&organization_billing)
        );
        assert_eq!(organization.projects.len(), 1);
        let project = &organization.projects[0];
        assert_eq!(project.billing_account_id.as_ref(), Some(&project_billing));
    }

    #[tokio::test]
    async fn create_organization_rejects_invalid_billing_account() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = TenancyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let err = service
            .create_organization(
                CreateOrganizationRequest {
                    name: String::from("Example Org"),
                    slug: String::from("example-org"),
                    billing_account_id: Some(String::from("bad-value")),
                },
                &context,
            )
            .await
            .expect_err("invalid billing account ids should be rejected");
        assert!(err.to_string().contains("invalid billing_account_id"));
    }

    #[tokio::test]
    async fn create_hierarchy_rejects_soft_deleted_parents_and_canonicalizes_inputs() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = TenancyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let response = service
            .create_organization(
                CreateOrganizationRequest {
                    name: String::from("  Example Org  "),
                    slug: String::from("  example-org  "),
                    billing_account_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);
        let organization = service
            .organizations
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        assert_eq!(organization.name, "Example Org");
        assert_eq!(organization.slug, "example-org");

        let err = service
            .create_organization(
                CreateOrganizationRequest {
                    name: String::from("Duplicate"),
                    slug: String::from("example-org"),
                    billing_account_id: None,
                },
                &context,
            )
            .await
            .expect_err("duplicate organization slugs should be rejected");
        assert!(err.to_string().contains("organization slug already exists"));

        let response = service
            .create_project(
                CreateProjectRequest {
                    organization_id: organization.id.to_string(),
                    name: String::from("  Core Platform  "),
                    slug: String::from("  core-platform  "),
                    billing_account_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);

        let err = service
            .create_project(
                CreateProjectRequest {
                    organization_id: organization.id.to_string(),
                    name: String::from("Duplicate"),
                    slug: String::from("core-platform"),
                    billing_account_id: None,
                },
                &context,
            )
            .await
            .expect_err("duplicate project slugs should be rejected");
        assert!(err.to_string().contains("project slug already exists"));

        let project = service
            .projects
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        assert_eq!(project.name, "Core Platform");
        assert_eq!(project.slug, "core-platform");

        let response = service
            .create_environment(
                CreateEnvironmentRequest {
                    project_id: project.id.to_string(),
                    name: String::from("  Production  "),
                    slug: String::from("  prod  "),
                    region: String::from("  US-EAST-1  "),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(response.status(), StatusCode::CREATED);
        let environment = service
            .environments
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))[0]
            .1
            .value
            .clone();
        assert_eq!(environment.name, "Production");
        assert_eq!(environment.slug, "prod");
        assert_eq!(environment.region, "us-east-1");

        service
            .organizations
            .soft_delete(organization.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let err = service
            .create_project(
                CreateProjectRequest {
                    organization_id: organization.id.to_string(),
                    name: String::from("New Project"),
                    slug: String::from("new-project"),
                    billing_account_id: None,
                },
                &context,
            )
            .await
            .expect_err("soft-deleted organizations should be rejected");
        assert!(err.to_string().contains("organization does not exist"));

        service
            .projects
            .soft_delete(project.id.as_str(), Some(1))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let err = service
            .create_environment(
                CreateEnvironmentRequest {
                    project_id: project.id.to_string(),
                    name: String::from("New Environment"),
                    slug: String::from("new-env"),
                    region: String::from("us-west-2"),
                },
                &context,
            )
            .await
            .expect_err("soft-deleted projects should be rejected");
        assert!(err.to_string().contains("project does not exist"));
    }

    #[tokio::test]
    async fn tenancy_summary_reflects_persisted_state_and_billing_links() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = TenancyService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let organization_billing =
            BillingAccountId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .create_organization(
                CreateOrganizationRequest {
                    name: String::from("Acme Corp"),
                    slug: String::from("acme"),
                    billing_account_id: Some(organization_billing.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let organization = active_values(
            service
                .organizations
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("missing organization"));

        let project_billing =
            BillingAccountId::generate().unwrap_or_else(|error| panic!("{error}"));
        service
            .create_project(
                CreateProjectRequest {
                    organization_id: organization.id.to_string(),
                    name: String::from("Infrastructure"),
                    slug: String::from("infrastructure"),
                    billing_account_id: Some(project_billing.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        service
            .create_project(
                CreateProjectRequest {
                    organization_id: organization.id.to_string(),
                    name: String::from("Platform"),
                    slug: String::from("platform"),
                    billing_account_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let project = active_values(
            service
                .projects
                .list()
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        )
        .into_iter()
        .find(|value| value.slug == "infrastructure")
        .unwrap_or_else(|| panic!("missing infrastructure project"));

        service
            .create_environment(
                CreateEnvironmentRequest {
                    project_id: project.id.to_string(),
                    name: String::from("Production"),
                    slug: String::from("prod"),
                    region: String::from("us-west-2"),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .tenancy_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(summary.total_organizations, 1);
        assert_eq!(summary.total_projects, 2);
        assert_eq!(summary.total_environments, 1);
        assert_eq!(summary.organizations_with_billing_account, 1);
        assert_eq!(summary.projects_with_billing_account, 1);
        assert_eq!(summary.billing_linked_organizations, 1);
        assert_eq!(summary.billing_linked_projects, 2);
    }

    #[test]
    fn active_values_filters_deleted_entries_and_sorts_by_key() {
        let active_id = OrganizationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let deleted_id = OrganizationId::generate().unwrap_or_else(|error| panic!("{error}"));
        let newer_id = OrganizationId::generate().unwrap_or_else(|error| panic!("{error}"));

        let records = vec![
            (
                deleted_id.to_string(),
                StoredDocument {
                    version: 2,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: true,
                    value: Organization {
                        id: deleted_id.clone(),
                        name: String::from("deleted"),
                        slug: String::from("deleted"),
                        metadata: ResourceMetadata::new(
                            OwnershipScope::Tenant,
                            Some(deleted_id.to_string()),
                            String::from("deleted"),
                        ),
                        billing_account_id: None,
                    },
                },
            ),
            (
                newer_id.to_string(),
                StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: Organization {
                        id: newer_id.clone(),
                        name: String::from("newer"),
                        slug: String::from("newer"),
                        metadata: ResourceMetadata::new(
                            OwnershipScope::Tenant,
                            Some(newer_id.to_string()),
                            String::from("newer"),
                        ),
                        billing_account_id: None,
                    },
                },
            ),
            (
                active_id.to_string(),
                StoredDocument {
                    version: 1,
                    updated_at: OffsetDateTime::now_utc(),
                    deleted: false,
                    value: Organization {
                        id: active_id.clone(),
                        name: String::from("active"),
                        slug: String::from("active"),
                        metadata: ResourceMetadata::new(
                            OwnershipScope::Tenant,
                            Some(active_id.to_string()),
                            String::from("active"),
                        ),
                        billing_account_id: None,
                    },
                },
            ),
        ];

        let values = active_values(records);
        assert_eq!(values.len(), 2);
        let mut actual_ids = values
            .into_iter()
            .map(|value| value.id.to_string())
            .collect::<Vec<_>>();
        actual_ids.sort();
        let mut expected_ids = vec![active_id.to_string(), newer_id.to_string()];
        expected_ids.sort();
        assert_eq!(actual_ids, expected_ids);
    }
}
