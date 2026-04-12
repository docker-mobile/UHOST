//! Lightweight service runtime for UHost.

mod idempotency;
mod topology;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Either, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use uhost_api::{
    ApiBody, DEFAULT_MAX_BODY_BYTES, box_body, error_response, full_body, json_response, read_body,
};
use uhost_core::{
    ErrorCode, JsonLogger, LogLevel, MetricRegistry, PlatformError, PrincipalIdentity,
    PrincipalKind, RequestContext, Result, SecretString,
};

pub use idempotency::HttpIdempotencyJournal;
use idempotency::{JournalBeginOutcome, PreparedIdempotencyRequest, StoredHttpResponse};
pub use topology::{
    RuntimeCellMembership, RuntimeDrainIntent, RuntimeEvacuationRollbackArtifact,
    RuntimeEvacuationRouteWithdrawalArtifact, RuntimeEvacuationTargetReadinessArtifact,
    RuntimeLeaseFreshness, RuntimeLeaseState, RuntimeLogicalServiceGroup,
    RuntimeParticipantCleanupStage, RuntimeParticipantCleanupWorkflow,
    RuntimeParticipantDegradedReason, RuntimeParticipantDrainPhase, RuntimeParticipantLeaseSource,
    RuntimeParticipantReconciliation, RuntimeParticipantRegistration, RuntimeParticipantState,
    RuntimeParticipantTombstoneHistoryEntry, RuntimeProcessRole, RuntimeProcessState,
    RuntimeReadinessState, RuntimeRegionMembership, RuntimeServiceGroupConflictState,
    RuntimeServiceGroupDirectoryEntry, RuntimeServiceGroupOwnership,
    RuntimeServiceGroupQuarantineReason, RuntimeServiceGroupQuarantineSummary,
    RuntimeServiceGroupRegistrationResolution, RuntimeTopology, RuntimeTopologyHandle,
};

/// Request body type accepted by runtime services.
pub type RequestBody = Either<Incoming, Full<Bytes>>;

/// Request envelope passed to runtime services.
pub type ServiceRequest = Request<RequestBody>;

/// Boxed response future used by service implementations.
pub type ResponseFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Response<ApiBody>>>> + Send + 'a>>;

/// Boxed authorization future used by runtime admission hooks.
pub type AuthorizationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<PrincipalIdentity>>> + Send + 'a>>;

/// Boxed response future used by runtime route forwarders.
pub type ForwardingFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<ApiBody>>> + Send + 'a>>;

/// Failure kinds that force the `/readyz` gate to fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeReadyzFailureReason {
    /// Runtime lease renewal failed and the process can no longer assert fresh ownership.
    LeaseRenewalFailed,
    /// Runtime topology publication failed and the process can no longer assert current state.
    TopologyPublicationFailed,
}

impl RuntimeReadyzFailureReason {
    /// Return the stable string form used by `/readyz` responses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseRenewalFailed => "lease_renewal_failed",
            Self::TopologyPublicationFailed => "topology_publication_failed",
        }
    }
}

/// One latched `/readyz` failure that should force the runtime closed until publication succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeReadyzFailure {
    /// Stable reason code for the failure.
    pub reason: RuntimeReadyzFailureReason,
    /// Detailed error text captured from the failing operation.
    pub detail: String,
}

impl RuntimeReadyzFailure {
    fn new(reason: RuntimeReadyzFailureReason, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let trimmed = detail.trim();
        Self {
            reason,
            detail: if trimmed.is_empty() {
                reason.as_str().to_owned()
            } else {
                trimmed.to_owned()
            },
        }
    }
}

/// Shared latch used by runtime controllers to force `/readyz` closed after critical failures.
#[derive(Debug, Clone, Default)]
pub struct RuntimeReadyzHandle {
    inner: Arc<StdRwLock<Option<RuntimeReadyzFailure>>>,
}

impl RuntimeReadyzHandle {
    /// Clear the latched `/readyz` failure after a successful publication.
    pub fn clear_failure(&self) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = None;
    }

    /// Latch one `/readyz` failure until a later successful publication clears it.
    pub fn fail(&self, reason: RuntimeReadyzFailureReason, detail: impl Into<String>) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) =
            Some(RuntimeReadyzFailure::new(reason, detail));
    }

    /// Snapshot the currently latched `/readyz` failure, if one exists.
    pub fn failure(&self) -> Option<RuntimeReadyzFailure> {
        self.inner
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }
}

/// Async authorizer for bearer tokens on service-facing routes.
pub trait BearerTokenAuthorizer: Send + Sync {
    /// Resolve a bearer token into a principal for the targeted route audience.
    fn authorize<'a>(&'a self, bearer_token: &'a str, audience: &'a str)
    -> AuthorizationFuture<'a>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteMatchKind {
    Exact,
    Prefix,
}

/// Explicit route ownership declared by a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteClaim {
    kind: RouteMatchKind,
    path: &'static str,
}

impl RouteClaim {
    /// Claim exactly one path.
    pub const fn exact(path: &'static str) -> Self {
        Self {
            kind: RouteMatchKind::Exact,
            path,
        }
    }

    /// Claim a segment-aware prefix, matching the prefix itself and descendants.
    pub const fn prefix(path: &'static str) -> Self {
        Self {
            kind: RouteMatchKind::Prefix,
            path,
        }
    }

    /// Borrow the claimed path.
    pub const fn path(self) -> &'static str {
        self.path
    }

    /// Check whether the claim owns the provided request path.
    pub fn matches(self, path: &str) -> bool {
        route_path_matches(self.path, path, self.kind)
    }

    fn overlaps(self, other: Self) -> bool {
        self.matches(other.path) || other.matches(self.path)
    }

    fn contains(self, other: Self) -> bool {
        match (self.kind, other.kind) {
            (RouteMatchKind::Exact, RouteMatchKind::Exact) => self.matches(other.path),
            (RouteMatchKind::Exact, RouteMatchKind::Prefix) => false,
            (RouteMatchKind::Prefix, RouteMatchKind::Exact)
            | (RouteMatchKind::Prefix, RouteMatchKind::Prefix) => self.matches(other.path),
        }
    }

    fn segment_count(self) -> usize {
        route_path_segments(self.path).len()
    }

    fn literal_segment_count(self) -> usize {
        route_path_segments(self.path)
            .into_iter()
            .filter(|segment| !is_route_parameter_segment(segment))
            .count()
    }
}

fn route_path_matches(pattern: &str, path: &str, kind: RouteMatchKind) -> bool {
    let pattern_segments = route_path_segments(pattern);
    let path_segments = route_path_segments(path);

    match kind {
        RouteMatchKind::Exact => {
            pattern_segments.len() == path_segments.len()
                && route_segment_slices_match(&pattern_segments, &path_segments)
        }
        RouteMatchKind::Prefix => {
            pattern_segments.len() <= path_segments.len()
                && route_segment_slices_match(
                    &pattern_segments,
                    &path_segments[..pattern_segments.len()],
                )
        }
    }
}

fn route_path_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn route_segment_slices_match(pattern: &[&str], path: &[&str]) -> bool {
    pattern
        .iter()
        .zip(path.iter())
        .all(|(pattern, path)| route_segment_matches(pattern, path))
}

fn route_segment_matches(pattern: &str, path: &str) -> bool {
    pattern == path || is_route_parameter_segment(pattern)
}

fn is_route_parameter_segment(segment: &str) -> bool {
    segment.len() > 2 && segment.starts_with('{') && segment.ends_with('}')
}

impl fmt::Display for RouteClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            RouteMatchKind::Exact => "exact",
            RouteMatchKind::Prefix => "prefix",
        };
        write!(formatter, "{kind} route `{}`", self.path)
    }
}

/// Explicit surface classification for a route family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSurface {
    /// Public runtime or service surface that may be served without bootstrap auth.
    Public,
    /// Tenant-facing control-plane surface.
    Tenant,
    /// Operator-only control-plane surface.
    Operator,
    /// Internal-only control-plane surface.
    Internal,
}

impl RouteSurface {
    /// Return the stable string form used by logs and contract metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Tenant => "tenant",
            Self::Operator => "operator",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for RouteSurface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Method family selector used by per-route admission metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMethodMatch {
    /// Match all HTTP methods.
    Any,
    /// Match safe, read-oriented HTTP methods.
    Safe,
    /// Match unsafe, mutating HTTP methods.
    Unsafe,
}

impl RouteMethodMatch {
    /// Return the stable string form used by logs and contract metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Safe => "safe",
            Self::Unsafe => "unsafe",
        }
    }

    fn matches(self, method: &Method) -> bool {
        match self {
            Self::Any => true,
            Self::Safe => is_safe_route_method(method),
            Self::Unsafe => !is_safe_route_method(method),
        }
    }

    const fn specificity_rank(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::Safe | Self::Unsafe => 1,
        }
    }
}

impl fmt::Display for RouteMethodMatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Request-class metadata enforced by runtime admission before a service handler runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRequestClass {
    /// Read-only route that workload, user, or operator principals may consume.
    Read,
    /// Read-only control-plane route that excludes workload principals.
    ControlRead,
    /// Synchronous control-plane mutation that excludes workload principals.
    Mutate,
    /// Async job-creating mutation that workload principals may initiate.
    AsyncMutate,
    /// Operator-only read that still remains reachable in explicit local-dev mode.
    OperatorRead,
    /// Operator-only mutation that still remains reachable in explicit local-dev mode.
    OperatorMutate,
    /// Operator-only destructive mutation that still remains reachable in explicit local-dev mode.
    OperatorDestructive,
}

impl RouteRequestClass {
    /// Return the stable string form used by logs and contract metadata.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::ControlRead => "control_read",
            Self::Mutate => "mutate",
            Self::AsyncMutate => "async_mutate",
            Self::OperatorRead => "operator_read",
            Self::OperatorMutate => "operator_mutate",
            Self::OperatorDestructive => "operator_destructive",
        }
    }
}

impl fmt::Display for RouteRequestClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One explicit route admission declaration bound to an owned route claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSurfaceBinding {
    claim: RouteClaim,
    surface: RouteSurface,
    method_match: RouteMethodMatch,
    request_class: RouteRequestClass,
}

impl RouteSurfaceBinding {
    /// Classify an exact route claim for every method family.
    pub const fn exact(
        path: &'static str,
        surface: RouteSurface,
        request_class: RouteRequestClass,
    ) -> Self {
        Self {
            claim: RouteClaim::exact(path),
            surface,
            method_match: RouteMethodMatch::Any,
            request_class,
        }
    }

    /// Classify an exact route claim for safe methods only.
    pub const fn exact_safe(
        path: &'static str,
        surface: RouteSurface,
        request_class: RouteRequestClass,
    ) -> Self {
        Self {
            claim: RouteClaim::exact(path),
            surface,
            method_match: RouteMethodMatch::Safe,
            request_class,
        }
    }

    /// Classify an exact route claim for unsafe methods only.
    pub const fn exact_unsafe(
        path: &'static str,
        surface: RouteSurface,
        request_class: RouteRequestClass,
    ) -> Self {
        Self {
            claim: RouteClaim::exact(path),
            surface,
            method_match: RouteMethodMatch::Unsafe,
            request_class,
        }
    }

    /// Classify a prefix route claim for every method family.
    pub const fn prefix(
        path: &'static str,
        surface: RouteSurface,
        request_class: RouteRequestClass,
    ) -> Self {
        Self {
            claim: RouteClaim::prefix(path),
            surface,
            method_match: RouteMethodMatch::Any,
            request_class,
        }
    }

    /// Classify a prefix route claim for safe methods only.
    pub const fn prefix_safe(
        path: &'static str,
        surface: RouteSurface,
        request_class: RouteRequestClass,
    ) -> Self {
        Self {
            claim: RouteClaim::prefix(path),
            surface,
            method_match: RouteMethodMatch::Safe,
            request_class,
        }
    }

    /// Classify a prefix route claim for unsafe methods only.
    pub const fn prefix_unsafe(
        path: &'static str,
        surface: RouteSurface,
        request_class: RouteRequestClass,
    ) -> Self {
        Self {
            claim: RouteClaim::prefix(path),
            surface,
            method_match: RouteMethodMatch::Unsafe,
            request_class,
        }
    }

    /// Borrow the classified route path.
    pub const fn path(self) -> &'static str {
        self.claim.path()
    }

    /// Return the match kind name used by contract manifests.
    pub const fn match_kind(self) -> &'static str {
        match self.claim.kind {
            RouteMatchKind::Exact => "exact",
            RouteMatchKind::Prefix => "prefix",
        }
    }

    /// Borrow the declared surface classification.
    pub const fn surface(self) -> RouteSurface {
        self.surface
    }

    /// Borrow the declared HTTP method family selector.
    pub const fn method_match(self) -> RouteMethodMatch {
        self.method_match
    }

    /// Borrow the declared request-class classification.
    pub const fn request_class(self) -> RouteRequestClass {
        self.request_class
    }
}

/// Route descriptor handed to runtime route forwarders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardedRoute {
    service_name: &'static str,
    surface: RouteSurface,
}

impl ForwardedRoute {
    /// Build one forwarded route descriptor.
    pub const fn new(service_name: &'static str, surface: RouteSurface) -> Self {
        Self {
            service_name,
            surface,
        }
    }

    /// Stable service name owning the forwarded route family.
    pub const fn service_name(self) -> &'static str {
        self.service_name
    }

    /// Declared surface classification for the forwarded route family.
    pub const fn surface(self) -> RouteSurface {
        self.surface
    }
}

/// Async route forwarder used for non-local route families.
pub trait RouteForwarder: Send + Sync {
    /// Forward one request to the owning peer for the provided route family.
    fn forward<'a>(
        &'a self,
        request: ServiceRequest,
        route: ForwardedRoute,
        context: RequestContext,
    ) -> ForwardingFuture<'a>;
}

/// Runtime registration for one non-local route family that should be forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardedServiceRegistration {
    service_name: &'static str,
    route_surfaces: &'static [RouteSurfaceBinding],
}

impl ForwardedServiceRegistration {
    /// Build one forwarded-service registration.
    pub const fn new(
        service_name: &'static str,
        route_surfaces: &'static [RouteSurfaceBinding],
    ) -> Self {
        Self {
            service_name,
            route_surfaces,
        }
    }

    /// Stable service name owning the forwarded route family.
    pub const fn service_name(self) -> &'static str {
        self.service_name
    }

    /// Explicit route-surface declarations for the forwarded family.
    pub const fn route_surfaces(self) -> &'static [RouteSurfaceBinding] {
        self.route_surfaces
    }
}

/// Static per-service route forwarder backed by direct peer socket addresses.
#[derive(Clone)]
pub struct StaticServiceForwarder {
    service_targets: Arc<BTreeMap<String, SocketAddr>>,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl StaticServiceForwarder {
    /// Build a static forwarder from service-name to peer-address mappings.
    pub fn new<I, S>(service_targets: I) -> Self
    where
        I: IntoIterator<Item = (S, SocketAddr)>,
        S: Into<String>,
    {
        let service_targets = service_targets
            .into_iter()
            .map(|(service_name, address)| (service_name.into(), address))
            .collect();
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        Self {
            service_targets: Arc::new(service_targets),
            client,
        }
    }

    async fn forward_request(
        &self,
        request: ServiceRequest,
        service_name: &str,
        target: SocketAddr,
    ) -> Result<Response<ApiBody>> {
        let path_and_query = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let uri = format!("http://{target}{path_and_query}")
            .parse::<http::Uri>()
            .map_err(|error| {
                PlatformError::unavailable("failed to build forwarded peer request")
                    .with_detail(error.to_string())
            })?;
        let (mut parts, body) = request.into_parts();
        let body = collect_request_body_with_limit(body, DEFAULT_MAX_BODY_BYTES).await?;
        parts.uri = uri;
        parts.headers.remove(header::HOST);
        let host = http::HeaderValue::from_str(&target.to_string()).map_err(|error| {
            PlatformError::invalid("failed to encode forwarded peer host")
                .with_detail(error.to_string())
        })?;
        parts.headers.insert(header::HOST, host);
        let forwarded = Request::from_parts(parts, Full::new(body));
        let response = self.client.request(forwarded).await.map_err(|error| {
            PlatformError::unavailable(format!(
                "failed to forward request for service `{service_name}`"
            ))
            .with_detail(error.to_string())
        })?;
        Ok(response_to_api_body(response))
    }
}

impl RouteForwarder for StaticServiceForwarder {
    fn forward<'a>(
        &'a self,
        request: ServiceRequest,
        route: ForwardedRoute,
        _context: RequestContext,
    ) -> ForwardingFuture<'a> {
        Box::pin(async move {
            let target = self
                .service_targets
                .get(route.service_name())
                .copied()
                .ok_or_else(|| {
                    PlatformError::unavailable(format!(
                        "no forward target configured for service `{}`",
                        route.service_name()
                    ))
                })?;
            self.forward_request(request, route.service_name(), target)
                .await
        })
    }
}

/// Explicit internal-route audience declaration bound to an owned route claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalRouteAudienceBinding {
    claim: RouteClaim,
    audience: &'static str,
}

impl InternalRouteAudienceBinding {
    /// Declare the audience for one exact internal route.
    pub const fn exact(path: &'static str, audience: &'static str) -> Self {
        Self {
            claim: RouteClaim::exact(path),
            audience,
        }
    }

    /// Declare the audience for one prefix internal route.
    pub const fn prefix(path: &'static str, audience: &'static str) -> Self {
        Self {
            claim: RouteClaim::prefix(path),
            audience,
        }
    }

    /// Borrow the declared route path.
    pub const fn path(self) -> &'static str {
        self.claim.path()
    }

    /// Return the match kind name used by catalog manifests.
    pub const fn match_kind(self) -> &'static str {
        match self.claim.kind {
            RouteMatchKind::Exact => "exact",
            RouteMatchKind::Prefix => "prefix",
        }
    }

    /// Borrow the required route audience.
    pub const fn audience(self) -> &'static str {
        self.audience
    }
}

/// Runtime registration for one HTTP service plus its explicit surface manifest.
pub struct ServiceRegistration {
    service: Arc<dyn HttpService>,
    route_surfaces: &'static [RouteSurfaceBinding],
    internal_route_audiences: &'static [InternalRouteAudienceBinding],
}

impl ServiceRegistration {
    /// Build a runtime registration with explicit route-surface declarations.
    pub fn new(
        service: Arc<dyn HttpService>,
        route_surfaces: &'static [RouteSurfaceBinding],
    ) -> Self {
        Self::new_with_internal_route_audiences(service, route_surfaces, &[])
    }

    /// Build a runtime registration with explicit route-surface and internal-audience declarations.
    pub fn new_with_internal_route_audiences(
        service: Arc<dyn HttpService>,
        route_surfaces: &'static [RouteSurfaceBinding],
        internal_route_audiences: &'static [InternalRouteAudienceBinding],
    ) -> Self {
        Self {
            service,
            route_surfaces,
            internal_route_audiences,
        }
    }
}

#[derive(Debug, Clone)]
struct RegisteredRoute {
    claim: RouteClaim,
    target: RegisteredRouteTarget,
    service_name: &'static str,
    surface: RouteSurface,
    method_match: RouteMethodMatch,
    request_class: RouteRequestClass,
    internal_audience: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegisteredRouteTarget {
    ReservedRuntime,
    LocalService(usize),
    ForwardedService(&'static str),
}

#[derive(Debug, Clone, Copy)]
struct RegisteredRouteClaim {
    claim: RouteClaim,
    target: RegisteredRouteTarget,
    service_name: &'static str,
}

#[derive(Debug, Clone)]
struct RouteRegistry {
    routes: Vec<RegisteredRoute>,
}

const RUNTIME_SERVICE_NAME: &str = "runtime";
const RESERVED_RUNTIME_ROUTE_SURFACES: [RouteSurfaceBinding; 4] = [
    RouteSurfaceBinding::exact_safe("/healthz", RouteSurface::Public, RouteRequestClass::Read),
    RouteSurfaceBinding::exact_safe("/readyz", RouteSurface::Public, RouteRequestClass::Read),
    RouteSurfaceBinding::exact_safe(
        "/metrics",
        RouteSurface::Operator,
        RouteRequestClass::OperatorRead,
    ),
    RouteSurfaceBinding::exact_safe(
        "/runtime/topology",
        RouteSurface::Operator,
        RouteRequestClass::OperatorRead,
    ),
];

impl RouteRegistry {
    fn build(
        services: &[ServiceRegistration],
        forwarded_services: &[ForwardedServiceRegistration],
    ) -> Result<Self> {
        let mut routes: Vec<RegisteredRoute> = RESERVED_RUNTIME_ROUTE_SURFACES
            .iter()
            .copied()
            .map(|binding| RegisteredRoute {
                claim: binding.claim,
                target: RegisteredRouteTarget::ReservedRuntime,
                service_name: RUNTIME_SERVICE_NAME,
                surface: binding.surface,
                method_match: binding.method_match,
                request_class: binding.request_class,
                internal_audience: None,
            })
            .collect();
        let mut route_claims: Vec<RegisteredRouteClaim> = RESERVED_RUNTIME_ROUTE_SURFACES
            .iter()
            .copied()
            .map(|binding| RegisteredRouteClaim {
                claim: binding.claim,
                target: RegisteredRouteTarget::ReservedRuntime,
                service_name: RUNTIME_SERVICE_NAME,
            })
            .collect();

        for (service_index, registration) in services.iter().enumerate() {
            let service_name = registration.service.name();
            let claims = registration.service.route_claims();
            if claims.is_empty() {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` must declare at least one route claim"
                )));
            }

            Self::validate_surface_bindings(service_name, claims, registration.route_surfaces)?;
            Self::validate_internal_route_audience_bindings(
                service_name,
                claims,
                registration.route_surfaces,
                registration.internal_route_audiences,
            )?;

            for claim in claims.iter().copied() {
                Self::validate_claim(service_name, claim)?;

                if let Some(existing) = route_claims
                    .iter()
                    .find(|existing| existing.claim.overlaps(claim))
                {
                    if matches!(existing.target, RegisteredRouteTarget::ReservedRuntime) {
                        return Err(PlatformError::conflict(format!(
                            "service `{service_name}` route claim {claim} overlaps reserved runtime route `{}`",
                            existing.claim.path()
                        )));
                    }

                    return Err(PlatformError::conflict(format!(
                        "service `{service_name}` route claim {claim} overlaps service `{}` {}",
                        existing.service_name, existing.claim
                    )));
                }

                route_claims.push(RegisteredRouteClaim {
                    claim,
                    target: RegisteredRouteTarget::LocalService(service_index),
                    service_name,
                });
            }

            for binding in registration.route_surfaces.iter().copied() {
                let internal_audience = registration
                    .internal_route_audiences
                    .iter()
                    .copied()
                    .find(|audience| audience.claim == binding.claim)
                    .map(|audience| audience.audience);

                routes.push(RegisteredRoute {
                    claim: binding.claim,
                    target: RegisteredRouteTarget::LocalService(service_index),
                    service_name,
                    surface: binding.surface,
                    method_match: binding.method_match,
                    request_class: binding.request_class,
                    internal_audience,
                });
            }
        }

        for forwarded in forwarded_services.iter().copied() {
            if forwarded.route_surfaces().is_empty() {
                return Err(PlatformError::invalid(format!(
                    "forwarded service `{}` must declare at least one route family",
                    forwarded.service_name()
                )));
            }

            for claim in Self::owned_forwarded_route_claims(forwarded.route_surfaces()) {
                Self::validate_claim(forwarded.service_name(), claim)?;

                if let Some(existing) = route_claims
                    .iter()
                    .find(|existing| existing.claim.overlaps(claim))
                {
                    if matches!(existing.target, RegisteredRouteTarget::ReservedRuntime) {
                        return Err(PlatformError::conflict(format!(
                            "forwarded service `{}` route claim {} overlaps reserved runtime route `{}`",
                            forwarded.service_name(),
                            claim,
                            existing.claim.path()
                        )));
                    }

                    return Err(PlatformError::conflict(format!(
                        "forwarded service `{}` route claim {} overlaps service `{}` {}",
                        forwarded.service_name(),
                        claim,
                        existing.service_name,
                        existing.claim
                    )));
                }

                route_claims.push(RegisteredRouteClaim {
                    claim,
                    target: RegisteredRouteTarget::ForwardedService(forwarded.service_name()),
                    service_name: forwarded.service_name(),
                });
            }

            for binding in forwarded.route_surfaces().iter().copied() {
                routes.push(RegisteredRoute {
                    claim: binding.claim,
                    target: RegisteredRouteTarget::ForwardedService(forwarded.service_name()),
                    service_name: forwarded.service_name(),
                    surface: binding.surface,
                    method_match: binding.method_match,
                    request_class: binding.request_class,
                    internal_audience: None,
                });
            }
        }

        Ok(Self { routes })
    }

    fn owned_forwarded_route_claims(route_surfaces: &[RouteSurfaceBinding]) -> Vec<RouteClaim> {
        let mut claims = Vec::new();
        for binding in route_surfaces.iter().copied() {
            if claims.contains(&binding.claim) {
                continue;
            }
            claims.push(binding.claim);
        }

        let all_claims = claims.clone();
        claims.retain(|candidate| {
            !all_claims
                .iter()
                .copied()
                .any(|other| other != *candidate && other.contains(*candidate))
        });
        claims
    }

    fn route_for_request(&self, method: &Method, path: &str) -> Result<Option<&RegisteredRoute>> {
        let mut matched: Option<&RegisteredRoute> = None;

        for route in &self.routes {
            if !route.claim.matches(path) || !route.method_match.matches(method) {
                continue;
            }

            if let Some(existing) = matched {
                if existing.target != route.target {
                    return Err(PlatformError::conflict(format!(
                        "multiple services claim request path `{path}` for method `{}`",
                        method.as_str()
                    ))
                    .with_detail(format!(
                        "service `{}` via {} and service `{}` via {}",
                        existing.service_name, existing.claim, route.service_name, route.claim
                    )));
                }

                match route.specificity_key().cmp(&existing.specificity_key()) {
                    std::cmp::Ordering::Greater => matched = Some(route),
                    std::cmp::Ordering::Less => {}
                    std::cmp::Ordering::Equal => {
                        if existing.claim != route.claim
                            || existing.method_match != route.method_match
                        {
                            return Err(PlatformError::conflict(format!(
                                "multiple route admission bindings match `{}` `{path}`",
                                method.as_str()
                            ))
                            .with_detail(format!(
                                "service `{}` via {} {} methods and service `{}` via {} {} methods",
                                existing.service_name,
                                existing.claim,
                                existing.method_match.as_str(),
                                route.service_name,
                                route.claim,
                                route.method_match.as_str(),
                            )));
                        }
                    }
                }
            } else {
                matched = Some(route);
            }
        }

        Ok(matched)
    }

    fn validate_claim(service_name: &str, claim: RouteClaim) -> Result<()> {
        if claim.path().len() > 1 && claim.path().ends_with('/') {
            return Err(PlatformError::invalid(format!(
                "service `{service_name}` route claim {claim} may not end with a trailing slash"
            )));
        }

        if matches!(claim.kind, RouteMatchKind::Prefix) && claim.path() == "/" {
            return Err(PlatformError::invalid(format!(
                "service `{service_name}` route claim {claim} is too broad"
            )));
        }

        let normalized = PlatformRuntime::canonicalize_path(claim.path())?;
        if normalized.as_ref() != claim.path() {
            return Err(PlatformError::invalid(format!(
                "service `{service_name}` route claim {claim} must be canonical"
            ))
            .with_detail(format!("use `{}` instead", normalized.as_ref())));
        }

        Ok(())
    }

    fn validate_surface_bindings(
        service_name: &str,
        claims: &[RouteClaim],
        route_surfaces: &[RouteSurfaceBinding],
    ) -> Result<()> {
        for claim in claims.iter().copied() {
            let matching_bindings = route_surfaces
                .iter()
                .copied()
                .filter(|binding| binding.claim == claim)
                .collect::<Vec<_>>();

            if matching_bindings.is_empty() {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` route claim {claim} must declare explicit surface classification"
                )));
            }

            let has_any = matching_bindings
                .iter()
                .any(|binding| binding.method_match == RouteMethodMatch::Any);
            let has_safe = has_any
                || matching_bindings
                    .iter()
                    .any(|binding| binding.method_match == RouteMethodMatch::Safe);
            let has_unsafe = has_any
                || matching_bindings
                    .iter()
                    .any(|binding| binding.method_match == RouteMethodMatch::Unsafe);
            if matches!(claim.kind, RouteMatchKind::Prefix) && (!has_safe || !has_unsafe) {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` route claim {claim} must declare explicit surface classification for both safe and unsafe methods"
                )));
            }
        }

        for binding in route_surfaces.iter().copied() {
            Self::validate_claim(service_name, binding.claim)?;
            if !claims
                .iter()
                .copied()
                .any(|claim| claim.contains(binding.claim))
            {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` surface classification {} route `{}` does not match an owned route claim",
                    binding.match_kind(),
                    binding.path()
                )));
            }

            let duplicate_count = route_surfaces
                .iter()
                .copied()
                .filter(|other| {
                    other.claim == binding.claim && other.method_match == binding.method_match
                })
                .count();
            if duplicate_count > 1 {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` route admission {} route `{}` has duplicate surface classifications for {} methods",
                    binding.match_kind(),
                    binding.path(),
                    binding.method_match.as_str()
                )));
            }
        }

        Ok(())
    }

    fn validate_internal_route_audience_bindings(
        service_name: &str,
        claims: &[RouteClaim],
        route_surfaces: &[RouteSurfaceBinding],
        internal_route_audiences: &[InternalRouteAudienceBinding],
    ) -> Result<()> {
        for claim in claims.iter().copied() {
            let surface = route_surfaces
                .iter()
                .copied()
                .find(|binding| binding.claim == claim)
                .map(|binding| binding.surface)
                .ok_or_else(|| {
                    PlatformError::invalid(format!(
                        "service `{service_name}` route claim {claim} must declare explicit surface classification"
                    ))
                })?;
            let matching_bindings = internal_route_audiences
                .iter()
                .copied()
                .filter(|binding| binding.claim == claim)
                .count();

            if surface == RouteSurface::Internal && matching_bindings == 0 {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` internal route claim {claim} must declare explicit internal audience"
                )));
            }

            if matching_bindings > 1 {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` internal route claim {claim} has duplicate internal audiences"
                )));
            }
        }

        for binding in internal_route_audiences.iter().copied() {
            Self::validate_internal_route_audience(service_name, binding)?;
            let surface = route_surfaces
                .iter()
                .copied()
                .find(|route_surface| route_surface.claim == binding.claim)
                .map(|route_surface| route_surface.surface)
                .ok_or_else(|| {
                    PlatformError::invalid(format!(
                        "service `{service_name}` internal audience {} route `{}` does not match an owned route claim",
                        binding.match_kind(),
                        binding.path()
                    ))
                })?;
            if surface != RouteSurface::Internal {
                return Err(PlatformError::invalid(format!(
                    "service `{service_name}` internal audience {} route `{}` must classify the route as internal",
                    binding.match_kind(),
                    binding.path()
                )));
            }
        }

        Ok(())
    }

    fn validate_internal_route_audience(
        service_name: &str,
        binding: InternalRouteAudienceBinding,
    ) -> Result<()> {
        let audience = binding.audience();
        if audience.trim().is_empty() {
            return Err(PlatformError::invalid(format!(
                "service `{service_name}` internal audience {} route `{}` may not be empty",
                binding.match_kind(),
                binding.path()
            )));
        }
        if audience.trim() != audience {
            return Err(PlatformError::invalid(format!(
                "service `{service_name}` internal audience {} route `{}` must be trimmed",
                binding.match_kind(),
                binding.path()
            )));
        }
        if audience.len() > 128 {
            return Err(PlatformError::invalid(format!(
                "service `{service_name}` internal audience {} route `{}` exceeds 128 bytes",
                binding.match_kind(),
                binding.path()
            )));
        }
        if !audience.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.' | ':')
        }) {
            return Err(PlatformError::invalid(format!(
                "service `{service_name}` internal audience {} route `{}` contains unsupported characters",
                binding.match_kind(),
                binding.path()
            )));
        }
        Ok(())
    }
}

/// Borrow the runtime-owned reserved route-surface manifest.
pub fn reserved_route_surfaces() -> &'static [RouteSurfaceBinding] {
    &RESERVED_RUNTIME_ROUTE_SURFACES
}

/// Runtime-level access gate configuration.
#[derive(Clone, Default)]
pub struct RuntimeAccessConfig {
    bootstrap_admin_token: Option<SecretString>,
    allow_unauthenticated_local_dev_service_routes: bool,
    bearer_token_authorizer: Option<Arc<dyn BearerTokenAuthorizer>>,
}

impl fmt::Debug for RuntimeAccessConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeAccessConfig")
            .field(
                "bootstrap_admin_token",
                &self.bootstrap_admin_token.as_ref().map(|_| "configured"),
            )
            .field(
                "allow_unauthenticated_local_dev_service_routes",
                &self.allow_unauthenticated_local_dev_service_routes,
            )
            .field(
                "bearer_token_authorizer",
                &self.bearer_token_authorizer.as_ref().map(|_| "configured"),
            )
            .finish()
    }
}

impl RuntimeAccessConfig {
    /// Build a new runtime access policy.
    pub fn new(bootstrap_admin_token: Option<SecretString>) -> Self {
        Self {
            bootstrap_admin_token,
            ..Self::default()
        }
    }

    /// Set or replace the bootstrap admin token.
    pub fn with_bootstrap_admin_token(mut self, token: SecretString) -> Self {
        self.bootstrap_admin_token = Some(token);
        self
    }

    /// Explicitly allow unauthenticated service-route access for loopback local development.
    pub fn with_unauthenticated_local_dev_service_routes(mut self) -> Self {
        self.allow_unauthenticated_local_dev_service_routes = true;
        self
    }

    /// Attach an async bearer-token authorizer for tenant service routes.
    pub fn with_bearer_token_authorizer(
        mut self,
        authorizer: Arc<dyn BearerTokenAuthorizer>,
    ) -> Self {
        self.bearer_token_authorizer = Some(authorizer);
        self
    }

    fn expected_bootstrap_token(&self) -> Option<&str> {
        self.bootstrap_admin_token
            .as_ref()
            .map(SecretString::expose)
    }

    fn allows_unauthenticated_local_dev_service_routes(&self) -> bool {
        self.allow_unauthenticated_local_dev_service_routes && self.bootstrap_admin_token.is_none()
    }
}

/// Trait implemented by each HTTP-facing service.
pub trait HttpService: Send + Sync {
    /// Stable service name.
    fn name(&self) -> &'static str;

    /// Explicit route claims owned by the service.
    fn route_claims(&self) -> &'static [RouteClaim];

    /// Whether the service owns the incoming path.
    fn matches(&self, path: &str) -> bool {
        self.route_claims()
            .iter()
            .copied()
            .any(|claim| claim.matches(path))
    }

    /// Handle the request, returning `None` when the path is not owned.
    fn handle<'a>(&'a self, request: ServiceRequest, context: RequestContext)
    -> ResponseFuture<'a>;
}

/// Shared runtime state.
#[derive(Clone)]
pub struct PlatformRuntime {
    services: Arc<Vec<Arc<dyn HttpService>>>,
    route_registry: Arc<RouteRegistry>,
    topology: RuntimeTopologyHandle,
    readyz: RuntimeReadyzHandle,
    idempotency_journal: Option<HttpIdempotencyJournal>,
    metrics: MetricRegistry,
    logger: JsonLogger,
    access: RuntimeAccessConfig,
    route_forwarder: Option<Arc<dyn RouteForwarder>>,
    connection_slots: Arc<Semaphore>,
    max_active_connections: usize,
    connection_timeout: Duration,
}

impl PlatformRuntime {
    const DEFAULT_MAX_ACTIVE_CONNECTIONS: usize = 16_384;
    const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

    /// Build a runtime from a set of services.
    pub fn new(services: Vec<ServiceRegistration>) -> Result<Self> {
        Self::new_with_forwarded_services(services, Vec::new())
    }

    /// Build a runtime from local services plus explicit non-local route families.
    pub fn new_with_forwarded_services(
        services: Vec<ServiceRegistration>,
        forwarded_services: Vec<ForwardedServiceRegistration>,
    ) -> Result<Self> {
        Self::build(
            services,
            forwarded_services,
            Self::DEFAULT_MAX_ACTIVE_CONNECTIONS,
            Self::DEFAULT_CONNECTION_TIMEOUT,
        )
    }

    fn build(
        services: Vec<ServiceRegistration>,
        forwarded_services: Vec<ForwardedServiceRegistration>,
        max_active_connections: usize,
        connection_timeout: Duration,
    ) -> Result<Self> {
        let max_active_connections = max_active_connections.max(1);
        let route_registry = Arc::new(RouteRegistry::build(&services, &forwarded_services)?);
        let services = Arc::new(
            services
                .into_iter()
                .map(|registration| registration.service)
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            services,
            route_registry,
            topology: RuntimeTopologyHandle::default(),
            readyz: RuntimeReadyzHandle::default(),
            idempotency_journal: None,
            metrics: MetricRegistry::default(),
            logger: JsonLogger,
            access: RuntimeAccessConfig::default(),
            route_forwarder: None,
            connection_slots: Arc::new(Semaphore::new(max_active_connections)),
            max_active_connections,
            connection_timeout: connection_timeout.max(Duration::from_secs(1)),
        })
    }

    /// Build a runtime with explicit network admission limits.
    pub fn new_with_network_limits(
        services: Vec<ServiceRegistration>,
        max_active_connections: usize,
        connection_timeout: Duration,
    ) -> Result<Self> {
        Self::build(
            services,
            Vec::new(),
            max_active_connections,
            connection_timeout,
        )
    }

    /// Attach a runtime-level access policy.
    pub fn with_access_config(mut self, access: RuntimeAccessConfig) -> Self {
        self.access = access;
        self
    }

    /// Attach a route forwarder for non-local route families.
    pub fn with_route_forwarder(mut self, route_forwarder: Arc<dyn RouteForwarder>) -> Self {
        self.route_forwarder = Some(route_forwarder);
        self
    }

    /// Replace the runtime topology handle with a shared handle.
    pub fn with_topology_handle(mut self, topology: RuntimeTopologyHandle) -> Self {
        self.topology = topology;
        self
    }

    /// Replace the shared `/readyz` latch used by the runtime.
    pub fn with_readyz_handle(mut self, readyz: RuntimeReadyzHandle) -> Self {
        self.readyz = readyz;
        self
    }

    /// Attach a durable idempotency journal for replay-safe retries.
    pub fn with_idempotency_journal(mut self, journal: HttpIdempotencyJournal) -> Self {
        self.idempotency_journal = Some(journal);
        self
    }

    /// Attach explicit process-role and logical topology metadata to the runtime.
    pub fn with_topology(self, topology: RuntimeTopology) -> Self {
        self.topology.replace(topology);
        self
    }

    /// Borrow the current runtime topology report.
    pub fn topology(&self) -> RuntimeTopology {
        self.topology.snapshot()
    }

    /// Borrow the shared topology handle used by the protected reporting surface.
    pub fn topology_handle(&self) -> RuntimeTopologyHandle {
        self.topology.clone()
    }

    /// Borrow the shared `/readyz` latch used by the runtime.
    pub fn readyz_handle(&self) -> RuntimeReadyzHandle {
        self.readyz.clone()
    }

    /// Borrow the metric registry.
    pub fn metrics(&self) -> &MetricRegistry {
        &self.metrics
    }

    /// Active connection and timeout limits enforced by the runtime.
    pub fn connection_limits(&self) -> (usize, Duration) {
        (self.max_active_connections, self.connection_timeout)
    }

    /// Dispatch one request across the registered services.
    pub async fn dispatch(&self, request: Request<Incoming>) -> Response<ApiBody> {
        // Runtime dispatch is intentionally linear: canonicalize the request
        // path, resolve the owning route, authorize against the route surface
        // and request class, short-circuit reserved runtime endpoints, and only
        // then deliver to a local service or forwarder with optional idempotent
        // replay.
        let path = match Self::canonicalize_path(request.uri().path()) {
            Ok(path) => path.into_owned(),
            Err(error) => return error_response(&error),
        };
        let method = request.method().clone();

        self.metrics.increment_counter("http.requests.total", 1);
        let mut context = match RequestContext::new() {
            Ok(context) => context,
            Err(error) => return error_response(&error),
        };
        let resolved_route = match self.resolve_request(&method, path.as_str()) {
            Ok(route) => route,
            Err(error) => return error_response(&error),
        };

        if let Err(error) = self
            .authorize_route(request.headers(), resolved_route.as_ref(), &mut context)
            .await
        {
            return error_response(&error);
        }

        if let Some(response) = self.special_response_for_resolved_route(resolved_route.as_ref()) {
            return response;
        }

        let mut log_fields = vec![
            uhost_core::LogField::new("method", method.as_str()),
            uhost_core::LogField::new("path", path.as_str()),
        ];
        if let Some(route) = resolved_route.as_ref() {
            log_fields.push(uhost_core::LogField::new("owner", route.service_name));
            log_fields.push(uhost_core::LogField::new("surface", route.surface.as_str()));
            log_fields.push(uhost_core::LogField::new(
                "request_class",
                route.request_class.as_str(),
            ));
        }

        self.logger.log(
            LogLevel::Info,
            "runtime",
            "request received",
            Some(&context),
            &log_fields,
        );

        if let Some(service) = resolved_route
            .as_ref()
            .and_then(RegisteredRoute::local_service_index)
            .and_then(|index| self.services.get(index))
        {
            let idempotency_key =
                match Self::extract_idempotency_key(request.headers(), request.method()) {
                    Ok(idempotency_key) => idempotency_key,
                    Err(error) => return error_response(&error),
                };

            if let (Some(idempotency_key), Some(journal), Some(route)) = (
                idempotency_key,
                self.idempotency_journal.as_ref(),
                resolved_route.as_ref(),
            ) {
                return self
                    .dispatch_idempotent_request(
                        service,
                        journal,
                        route,
                        request,
                        path.as_str(),
                        idempotency_key,
                        context,
                    )
                    .await;
            }

            return self
                .dispatch_service_request(service, request.map(Either::Left), context, &path)
                .await;
        }

        if let Some(route) = resolved_route
            .as_ref()
            .and_then(RegisteredRoute::forwarded_route)
        {
            let idempotency_key =
                match Self::extract_idempotency_key(request.headers(), request.method()) {
                    Ok(idempotency_key) => idempotency_key,
                    Err(error) => return error_response(&error),
                };

            if let (Some(idempotency_key), Some(journal)) =
                (idempotency_key, self.idempotency_journal.as_ref())
            {
                return self
                    .dispatch_idempotent_forwarded_request(
                        journal,
                        route,
                        request,
                        path.as_str(),
                        idempotency_key,
                        context,
                    )
                    .await;
            }

            return self
                .dispatch_forwarded_request(route, request.map(Either::Left), context, &path)
                .await;
        }

        Self::not_found_response(&path)
    }

    async fn dispatch_service_request(
        &self,
        service: &Arc<dyn HttpService>,
        request: ServiceRequest,
        context: RequestContext,
        path: &str,
    ) -> Response<ApiBody> {
        match service.handle(request, context).await {
            Ok(Some(response)) => response,
            Ok(None) => Self::not_found_response(path),
            Err(error) => error_response(&error),
        }
    }

    async fn dispatch_forwarded_request(
        &self,
        route: ForwardedRoute,
        request: ServiceRequest,
        context: RequestContext,
        path: &str,
    ) -> Response<ApiBody> {
        let Some(route_forwarder) = self.route_forwarder.as_ref() else {
            return error_response(
                &PlatformError::unavailable(format!(
                    "route family for service `{}` is not active locally",
                    route.service_name()
                ))
                .with_detail(format!(
                    "request path `{path}` matched a configured forwarded route but no route forwarder is attached"
                )),
            );
        };

        match route_forwarder.forward(request, route, context).await {
            Ok(response) => response,
            Err(error) => error_response(&error),
        }
    }

    async fn dispatch_idempotent_request(
        &self,
        service: &Arc<dyn HttpService>,
        journal: &HttpIdempotencyJournal,
        _route: &RegisteredRoute,
        request: Request<Incoming>,
        canonical_path: &str,
        idempotency_key: String,
        context: RequestContext,
    ) -> Response<ApiBody> {
        let (parts, body) = request.into_parts();
        let method = parts.method.clone();
        let query = parts.uri.query().map(str::to_owned);
        let buffered_body = match read_body(Request::new(body)).await {
            Ok(buffered_body) => buffered_body,
            Err(error) => return error_response(&error),
        };

        let request_digest =
            Self::request_digest(&method, canonical_path, query.as_deref(), &buffered_body);
        let journal_request = PreparedIdempotencyRequest::from_context(
            canonical_path,
            request_digest,
            idempotency_key,
            &method,
            &context,
        );

        let pending = match journal.begin(journal_request).await {
            Ok(JournalBeginOutcome::Replay(response)) => {
                self.metrics
                    .increment_counter("http.idempotency.replayed", 1);
                self.logger.log(
                    LogLevel::Info,
                    "runtime",
                    "idempotent response replayed",
                    Some(&context),
                    &[uhost_core::LogField::new("path", canonical_path)],
                );
                return response;
            }
            Ok(JournalBeginOutcome::Proceed(pending)) => pending,
            Err(error) => return error_response(&error),
        };

        let response = self
            .dispatch_service_request(
                service,
                Request::from_parts(parts, Either::Right(Full::new(buffered_body))),
                context,
                canonical_path,
            )
            .await;
        let (stored_response, response) = match StoredHttpResponse::capture(response).await {
            Ok(captured) => captured,
            Err(error) => return error_response(&error),
        };
        if let Err(error) = journal.complete(pending, stored_response).await {
            self.logger.log(
                LogLevel::Error,
                "runtime",
                "failed to persist idempotent response",
                None,
                &[
                    uhost_core::LogField::new("path", canonical_path),
                    uhost_core::LogField::new("detail", error.to_string()),
                ],
            );
        }
        response
    }

    async fn dispatch_idempotent_forwarded_request(
        &self,
        journal: &HttpIdempotencyJournal,
        route: ForwardedRoute,
        request: Request<Incoming>,
        canonical_path: &str,
        idempotency_key: String,
        context: RequestContext,
    ) -> Response<ApiBody> {
        let (parts, body) = request.into_parts();
        let method = parts.method.clone();
        let query = parts.uri.query().map(str::to_owned);
        let buffered_body = match read_body(Request::new(body)).await {
            Ok(buffered_body) => buffered_body,
            Err(error) => return error_response(&error),
        };

        let request_digest =
            Self::request_digest(&method, canonical_path, query.as_deref(), &buffered_body);
        let journal_request = PreparedIdempotencyRequest::from_context(
            canonical_path,
            request_digest,
            idempotency_key,
            &method,
            &context,
        );

        let pending = match journal.begin(journal_request).await {
            Ok(JournalBeginOutcome::Replay(response)) => {
                self.metrics
                    .increment_counter("http.idempotency.replayed", 1);
                self.logger.log(
                    LogLevel::Info,
                    "runtime",
                    "idempotent response replayed",
                    Some(&context),
                    &[uhost_core::LogField::new("path", canonical_path)],
                );
                return response;
            }
            Ok(JournalBeginOutcome::Proceed(pending)) => pending,
            Err(error) => return error_response(&error),
        };

        let response = self
            .dispatch_forwarded_request(
                route,
                Request::from_parts(parts, Either::Right(Full::new(buffered_body))),
                context,
                canonical_path,
            )
            .await;
        let (stored_response, response) = match StoredHttpResponse::capture(response).await {
            Ok(captured) => captured,
            Err(error) => return error_response(&error),
        };
        if let Err(error) = journal.complete(pending, stored_response).await {
            self.logger.log(
                LogLevel::Error,
                "runtime",
                "failed to persist idempotent response",
                None,
                &[
                    uhost_core::LogField::new("path", canonical_path),
                    uhost_core::LogField::new("detail", error.to_string()),
                ],
            );
        }
        response
    }

    /// Run an HTTP server until the process receives Ctrl-C.
    pub async fn serve(&self, address: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(address).await.map_err(|error| {
            PlatformError::unavailable("failed to bind listener").with_detail(error.to_string())
        })?;

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, _) = match accept_result {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(error) => {
                            self.logger.log(
                                LogLevel::Error,
                                "runtime",
                                "failed to accept connection",
                                None,
                                &[uhost_core::LogField::new("detail", error.to_string())],
                            );
                            return Err(PlatformError::unavailable("failed to accept connection")
                                .with_detail(error.to_string()));
                        }
                    };

                    let permit = match self.connection_slots.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            self.metrics.increment_counter("http.connections.rejected", 1);
                            self.logger.log(
                                LogLevel::Error,
                                "runtime",
                                "connection rejected: active connection limit reached",
                                None,
                                &[uhost_core::LogField::new(
                                    "max_active_connections",
                                    self.max_active_connections.to_string(),
                                )],
                            );
                            continue;
                        }
                    };
                    self.metrics.set_gauge(
                        "http.connections.active",
                        self.active_connection_count() as f64,
                    );

                    let runtime = self.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let io = TokioIo::new(stream);
                        let runtime_for_service = runtime.clone();
                        let service = service_fn(move |request| {
                            let runtime = runtime_for_service.clone();
                            async move {
                                let response = runtime.dispatch(request).await;
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });

                        let result = timeout(
                            runtime.connection_timeout,
                            http1::Builder::new()
                                .keep_alive(false)
                                .serve_connection(io, service),
                        )
                        .await;
                        match result {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                runtime.logger.log(
                                    LogLevel::Error,
                                    "runtime",
                                    "connection terminated with error",
                                    None,
                                    &[uhost_core::LogField::new("detail", error.to_string())],
                                );
                            }
                            Err(_) => {
                                runtime.metrics.increment_counter("http.connections.timed_out", 1);
                                runtime.logger.log(
                                    LogLevel::Error,
                                    "runtime",
                                    "connection exceeded runtime timeout",
                                    None,
                                    &[uhost_core::LogField::new(
                                        "timeout_seconds",
                                        runtime.connection_timeout.as_secs().to_string(),
                                    )],
                                );
                            }
                        }
                        runtime.metrics.set_gauge(
                            "http.connections.active",
                            runtime.active_connection_count() as f64,
                        );
                    });
                }
                ctrl_c = tokio::signal::ctrl_c() => {
                    if let Err(error) = ctrl_c {
                        return Err(PlatformError::unavailable("failed to register ctrl-c handler")
                            .with_detail(error.to_string()));
                    }

                    self.logger.log(LogLevel::Info, "runtime", "shutdown requested", None, &[]);
                    return Ok(());
                }
            }
        }
    }

    #[cfg(test)]
    fn special_response_for_path(&self, path: &str) -> Option<Response<ApiBody>> {
        let resolved_route = self.resolve_request_path(path).ok().flatten();
        self.special_response_for_resolved_route(resolved_route.as_ref())
    }

    fn special_response_for_resolved_route(
        &self,
        route: Option<&RegisteredRoute>,
    ) -> Option<Response<ApiBody>> {
        match route
            .filter(|route| route.is_reserved_runtime())
            .map(|route| route.claim.path())
        {
            Some("/healthz") => Some(
                json_response(StatusCode::OK, &serde_json::json!({ "status": "ok" }))
                    .unwrap_or_else(|error| error_response(&error)),
            ),
            Some("/readyz") => Some(self.readyz_response()),
            Some("/metrics") => Some(
                json_response(StatusCode::OK, &self.metrics.snapshot())
                    .unwrap_or_else(|error| error_response(&error)),
            ),
            Some("/runtime/topology") => {
                let topology = self.topology();
                Some(
                    json_response(StatusCode::OK, &topology)
                        .unwrap_or_else(|error| error_response(&error)),
                )
            }
            _ => None,
        }
    }

    fn readyz_response(&self) -> Response<ApiBody> {
        let topology = self.topology();
        let (status, body) = if let Some(failure) = self.readyz.failure() {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "status": "unready",
                    "reason": failure.reason.as_str(),
                    "detail": failure.detail,
                }),
            )
        } else {
            match topology.process_state {
                None => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "status": "starting",
                        "reason": "process_state_unavailable",
                    }),
                ),
                Some(process_state) if process_state.readiness != RuntimeReadinessState::Ready => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "status": "starting",
                        "reason": "process_not_ready",
                    }),
                ),
                Some(process_state)
                    if process_state.drain_intent != RuntimeDrainIntent::Serving =>
                {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        serde_json::json!({
                            "status": "draining",
                            "reason": "drain_requested",
                        }),
                    )
                }
                Some(process_state)
                    if process_state.lease.freshness == RuntimeLeaseFreshness::Stale =>
                {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        serde_json::json!({
                            "status": "unready",
                            "reason": "lease_stale",
                        }),
                    )
                }
                Some(process_state)
                    if process_state.lease.freshness == RuntimeLeaseFreshness::Expired =>
                {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        serde_json::json!({
                            "status": "unready",
                            "reason": "lease_expired",
                        }),
                    )
                }
                Some(_) => (
                    StatusCode::OK,
                    serde_json::json!({
                        "status": "ready",
                    }),
                ),
            }
        };

        json_response(status, &body).unwrap_or_else(|error| error_response(&error))
    }

    fn not_found_response(path: &str) -> Response<ApiBody> {
        error_response(&PlatformError::not_found(format!("no route for `{path}`")))
    }

    fn resolve_request(&self, method: &Method, path: &str) -> Result<Option<RegisteredRoute>> {
        self.route_registry
            .route_for_request(method, normalize_reserved_runtime_path(path))
            .map(|route| route.cloned())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn resolve_request_path(&self, path: &str) -> Result<Option<RegisteredRoute>> {
        self.resolve_request(&Method::GET, path)
    }

    #[cfg(test)]
    fn authorize_request(
        &self,
        headers: &HeaderMap,
        path: &str,
        context: &mut RequestContext,
    ) -> Result<()> {
        self.authorize_request_with_method(headers, &Method::GET, path, context)
    }

    #[cfg(test)]
    fn authorize_request_with_method(
        &self,
        headers: &HeaderMap,
        method: &Method,
        path: &str,
        context: &mut RequestContext,
    ) -> Result<()> {
        let route = self.resolve_request(method, path)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                PlatformError::unavailable("failed to build test authorization runtime")
                    .with_detail(error.to_string())
            })?;
        runtime.block_on(self.authorize_route(headers, route.as_ref(), context))
    }

    async fn authorize_route(
        &self,
        headers: &HeaderMap,
        route: Option<&RegisteredRoute>,
        context: &mut RequestContext,
    ) -> Result<()> {
        let Some(route) = route else {
            return Ok(());
        };

        match route.surface {
            RouteSurface::Public => Ok(()),
            RouteSurface::Tenant => self.authorize_tenant_route(headers, route, context).await,
            RouteSurface::Operator => self.authorize_bootstrap_token(headers, context),
            RouteSurface::Internal => self.authorize_internal_route(headers, route, context).await,
        }?;

        // Surface authorization chooses which credential path is allowed;
        // request-class authorization then narrows that authenticated principal
        // to the exact read/write/operator capability this route expects.
        self.authorize_request_class(route, context)
    }

    async fn authorize_tenant_route(
        &self,
        headers: &HeaderMap,
        route: &RegisteredRoute,
        context: &mut RequestContext,
    ) -> Result<()> {
        if route.is_local_service()
            && self
                .access
                .allows_unauthenticated_local_dev_service_routes()
        {
            return Ok(());
        }

        if self.try_authorize_bootstrap_token(headers, context) {
            return Ok(());
        }

        if let Some(principal) = self
            .authorize_bearer_token(headers, route.authorization_audience())
            .await?
        {
            context.set_principal(principal);
            return Ok(());
        }

        self.authorize_bootstrap_token(headers, context)
    }

    async fn authorize_internal_route(
        &self,
        headers: &HeaderMap,
        route: &RegisteredRoute,
        context: &mut RequestContext,
    ) -> Result<()> {
        let Some(principal) = self
            .authorize_bearer_token(headers, route.authorization_audience())
            .await?
        else {
            return Err(PlatformError::new(
                ErrorCode::Unauthorized,
                "internal routes require service identity bearer token",
            ));
        };

        if !Self::is_service_identity_principal(&principal) {
            return Err(PlatformError::new(
                ErrorCode::Unauthorized,
                "internal routes require service identity bearer token",
            ));
        }

        context.set_principal(principal);
        Ok(())
    }

    fn authorize_request_class(
        &self,
        route: &RegisteredRoute,
        context: &RequestContext,
    ) -> Result<()> {
        match route.request_class {
            RouteRequestClass::Read | RouteRequestClass::AsyncMutate => Ok(()),
            RouteRequestClass::ControlRead | RouteRequestClass::Mutate => {
                if context
                    .principal
                    .as_ref()
                    .is_some_and(|principal| principal.kind == PrincipalKind::Workload)
                {
                    return Err(PlatformError::forbidden(format!(
                        "route request class `{}` requires authenticated non-workload principal",
                        route.request_class.as_str()
                    ))
                    .with_correlation_id(context.correlation_id.clone()));
                }

                Ok(())
            }
            RouteRequestClass::OperatorRead
            | RouteRequestClass::OperatorMutate
            | RouteRequestClass::OperatorDestructive => {
                if context
                    .principal
                    .as_ref()
                    .is_some_and(|principal| principal.kind != PrincipalKind::Operator)
                {
                    return Err(PlatformError::forbidden(format!(
                        "route request class `{}` requires operator principal",
                        route.request_class.as_str()
                    ))
                    .with_correlation_id(context.correlation_id.clone()));
                }

                Ok(())
            }
        }
    }

    fn try_authorize_bootstrap_token(
        &self,
        headers: &HeaderMap,
        context: &mut RequestContext,
    ) -> bool {
        let Some(expected_token) = self.access.expected_bootstrap_token() else {
            return false;
        };
        let Some(provided_token) = Self::extract_bootstrap_token(headers) else {
            return false;
        };
        if provided_token != expected_token {
            return false;
        }

        Self::set_bootstrap_principal(context);
        true
    }

    async fn authorize_bearer_token(
        &self,
        headers: &HeaderMap,
        audience: &str,
    ) -> Result<Option<PrincipalIdentity>> {
        let Some(authorizer) = self.access.bearer_token_authorizer.as_ref() else {
            return Ok(None);
        };
        let Some(bearer_token) = Self::extract_authorization_bearer_token(headers) else {
            return Ok(None);
        };

        authorizer.authorize(bearer_token, audience).await
    }

    fn authorize_bootstrap_token(
        &self,
        headers: &HeaderMap,
        context: &mut RequestContext,
    ) -> Result<()> {
        let Some(expected_token) = self.access.expected_bootstrap_token() else {
            return Err(PlatformError::new(
                ErrorCode::Unauthorized,
                "protected routes require configured bootstrap admin token",
            ));
        };
        let Some(provided_token) = Self::extract_bootstrap_token(headers) else {
            return Err(PlatformError::new(
                ErrorCode::Unauthorized,
                "bootstrap admin token required",
            ));
        };
        if provided_token != expected_token {
            return Err(PlatformError::new(
                ErrorCode::Unauthorized,
                "invalid bootstrap admin token",
            ));
        }

        Self::set_bootstrap_principal(context);
        Ok(())
    }

    fn set_bootstrap_principal(context: &mut RequestContext) {
        context.set_principal(
            PrincipalIdentity::new(PrincipalKind::Operator, "bootstrap_admin")
                .with_credential_id("bootstrap_admin_token"),
        );
    }

    fn extract_authorization_bearer_token(headers: &HeaderMap) -> Option<&str> {
        if let Some(value) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            && let Some(token) = value.strip_prefix("Bearer ")
        {
            let trimmed = token.trim();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }

        None
    }

    fn extract_bootstrap_token(headers: &HeaderMap) -> Option<&str> {
        Self::extract_authorization_bearer_token(headers).or_else(|| {
            headers
                .get("x-uhost-admin-token")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
    }

    fn extract_idempotency_key(
        headers: &HeaderMap,
        method: &http::Method,
    ) -> Result<Option<String>> {
        if !matches!(
            *method,
            http::Method::POST | http::Method::PUT | http::Method::PATCH | http::Method::DELETE
        ) {
            return Ok(None);
        }

        let Some(value) = headers
            .get("idempotency-key")
            .or_else(|| headers.get("x-idempotency-key"))
        else {
            return Ok(None);
        };
        let value = value.to_str().map_err(|error| {
            PlatformError::invalid("Idempotency-Key header must be valid ASCII")
                .with_detail(error.to_string())
        })?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(PlatformError::invalid(
                "Idempotency-Key header may not be empty",
            ));
        }
        if trimmed.len() > 128 {
            return Err(PlatformError::invalid(
                "Idempotency-Key header may not exceed 128 characters",
            ));
        }
        Ok(Some(trimmed.to_owned()))
    }

    fn request_digest(
        method: &http::Method,
        path: &str,
        query: Option<&str>,
        body: &Bytes,
    ) -> String {
        let mut digest_input =
            format!("runtime-http-request:v1|{}|{path}|", method.as_str()).into_bytes();
        if let Some(query) = query {
            digest_input.extend_from_slice(query.as_bytes());
        }
        digest_input.push(b'|');
        digest_input.extend_from_slice(body);
        uhost_core::sha256_hex(&digest_input)
    }

    fn active_connection_count(&self) -> usize {
        self.max_active_connections
            .saturating_sub(self.connection_slots.available_permits())
    }

    fn is_service_identity_principal(principal: &PrincipalIdentity) -> bool {
        if principal.kind != PrincipalKind::Workload || principal.validate().is_err() {
            return false;
        }

        let normalized = principal.subject.trim().to_ascii_lowercase();
        let Some(subject) = normalized.strip_prefix("svc:") else {
            return false;
        };
        if subject.is_empty() || normalized != principal.subject {
            return false;
        }
        subject.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '-' | '_' | '.')
        })
    }

    fn canonicalize_path(path: &str) -> Result<Cow<'_, str>> {
        if path.is_empty() || !path.starts_with('/') {
            return Err(PlatformError::invalid("request path must be absolute"));
        }

        if path.bytes().any(|byte| byte == 0 || byte == b'\\') {
            return Err(
                PlatformError::invalid("request path contains invalid characters")
                    .with_detail(path.to_owned()),
            );
        }

        let preserve_trailing_slash = path.ends_with('/') && path != "/";
        let mut segments = Vec::new();
        for segment in path.split('/') {
            match segment {
                "" | "." => continue,
                ".." => {
                    return Err(PlatformError::invalid(
                        "request path may not contain `..` segments",
                    )
                    .with_detail(path.to_owned()));
                }
                segment => segments.push(segment),
            }
        }

        let mut normalized = String::with_capacity(path.len().saturating_add(1));
        normalized.push('/');
        normalized.push_str(&segments.join("/"));
        if preserve_trailing_slash && normalized != "/" {
            normalized.push('/');
        }

        if normalized == path {
            Ok(Cow::Borrowed(path))
        } else {
            Ok(Cow::Owned(normalized))
        }
    }
}

async fn collect_incoming_body_with_limit(mut body: Incoming, max_bytes: usize) -> Result<Bytes> {
    let mut collected = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            PlatformError::invalid("failed to read HTTP body").with_detail(error.to_string())
        })?;
        if let Ok(chunk) = frame.into_data() {
            if collected.len().saturating_add(chunk.len()) > max_bytes {
                return Err(
                    PlatformError::invalid("HTTP body exceeds maximum allowed size")
                        .with_detail(format!("max_bytes={max_bytes}")),
                );
            }
            collected.extend_from_slice(&chunk);
        }
    }
    Ok(collected.freeze())
}

async fn collect_request_body_with_limit(body: RequestBody, max_bytes: usize) -> Result<Bytes> {
    match body {
        Either::Left(body) => collect_incoming_body_with_limit(body, max_bytes).await,
        Either::Right(body) => {
            let body = body.collect().await.map_err(|error| {
                PlatformError::invalid("failed to read HTTP body").with_detail(error.to_string())
            })?;
            let body = body.to_bytes();
            if body.len() > max_bytes {
                return Err(
                    PlatformError::invalid("HTTP body exceeds maximum allowed size")
                        .with_detail(format!("max_bytes={max_bytes}")),
                );
            }
            Ok(body)
        }
    }
}

fn response_to_api_body(response: Response<Incoming>) -> Response<ApiBody> {
    let (parts, body) = response.into_parts();
    let body = box_body(body.map_err(io::Error::other));
    Response::from_parts(parts, body)
}

impl RegisteredRoute {
    fn specificity_key(&self) -> (u8, usize, usize, usize, u8) {
        let match_kind_rank = match self.claim.kind {
            RouteMatchKind::Exact => 1,
            RouteMatchKind::Prefix => 0,
        };
        (
            match_kind_rank,
            self.claim.literal_segment_count(),
            self.claim.segment_count(),
            self.claim.path().len(),
            self.method_match.specificity_rank(),
        )
    }

    fn is_reserved_runtime(&self) -> bool {
        matches!(self.target, RegisteredRouteTarget::ReservedRuntime)
    }

    fn is_local_service(&self) -> bool {
        matches!(self.target, RegisteredRouteTarget::LocalService(_))
    }

    fn local_service_index(&self) -> Option<usize> {
        match self.target {
            RegisteredRouteTarget::LocalService(index) => Some(index),
            RegisteredRouteTarget::ReservedRuntime | RegisteredRouteTarget::ForwardedService(_) => {
                None
            }
        }
    }

    fn forwarded_route(&self) -> Option<ForwardedRoute> {
        match self.target {
            RegisteredRouteTarget::ForwardedService(service_name) => {
                Some(ForwardedRoute::new(service_name, self.surface))
            }
            RegisteredRouteTarget::ReservedRuntime | RegisteredRouteTarget::LocalService(_) => None,
        }
    }

    fn authorization_audience(&self) -> &str {
        self.internal_audience.unwrap_or(self.service_name)
    }
}

fn is_safe_route_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

fn normalize_reserved_runtime_path(path: &str) -> &str {
    match path {
        "/healthz/" => "/healthz",
        "/readyz/" => "/readyz",
        "/metrics/" => "/metrics",
        "/runtime/topology/" => "/runtime/topology",
        _ => path,
    }
}

/// Small helper used by console responses.
pub fn html_response(status: StatusCode, html: impl Into<String>) -> Result<Response<ApiBody>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(bytes::Bytes::from(html.into())))
        .map_err(|error| {
            PlatformError::new(
                uhost_core::ErrorCode::Internal,
                "failed to build html response",
            )
            .with_detail(error.to_string())
        })
}

/// Small wrapper for HTML dashboards and status pages.
#[derive(Debug, Clone, Serialize)]
pub struct StatusPage {
    /// Page title.
    pub title: String,
    /// Status summary.
    pub summary: String,
    /// Named counters and health summaries.
    pub cards: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use hyper::body::{Body, Frame};
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use uhost_types::ServiceMode;

    const fn tenant_prefix_safe(path: &'static str) -> RouteSurfaceBinding {
        RouteSurfaceBinding::prefix_safe(path, RouteSurface::Tenant, RouteRequestClass::Read)
    }

    const fn tenant_prefix_unsafe(path: &'static str) -> RouteSurfaceBinding {
        RouteSurfaceBinding::prefix_unsafe(
            path,
            RouteSurface::Tenant,
            RouteRequestClass::AsyncMutate,
        )
    }

    const fn operator_prefix_safe(path: &'static str) -> RouteSurfaceBinding {
        RouteSurfaceBinding::prefix_safe(
            path,
            RouteSurface::Operator,
            RouteRequestClass::OperatorRead,
        )
    }

    const fn operator_prefix_unsafe(path: &'static str) -> RouteSurfaceBinding {
        RouteSurfaceBinding::prefix_unsafe(
            path,
            RouteSurface::Operator,
            RouteRequestClass::OperatorMutate,
        )
    }

    const COLLIDING_ROUTE_CLAIMS: &[RouteClaim] = &[RouteClaim::exact("/healthz")];
    const COLLIDING_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[RouteSurfaceBinding::exact(
        "/healthz",
        RouteSurface::Tenant,
        RouteRequestClass::Read,
    )];
    const TOPOLOGY_COLLIDING_ROUTE_CLAIMS: &[RouteClaim] =
        &[RouteClaim::exact("/runtime/topology")];
    const TOPOLOGY_COLLIDING_ROUTE_SURFACES: &[RouteSurfaceBinding] =
        &[RouteSurfaceBinding::exact(
            "/runtime/topology",
            RouteSurface::Tenant,
            RouteRequestClass::Read,
        )];
    const IDENTITY_ROUTE_CLAIMS: &[RouteClaim] = &[RouteClaim::prefix("/identity")];
    const IDENTITY_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        tenant_prefix_safe("/identity"),
        tenant_prefix_unsafe("/identity"),
    ];
    const FORWARDED_IDENTITY_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        RouteSurfaceBinding::exact_safe("/identity", RouteSurface::Tenant, RouteRequestClass::Read),
        tenant_prefix_safe("/identity"),
        tenant_prefix_unsafe("/identity"),
    ];
    const IDENTITY_EXTRA_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        tenant_prefix_safe("/identity"),
        tenant_prefix_unsafe("/identity"),
        RouteSurfaceBinding::exact("/tenancy", RouteSurface::Tenant, RouteRequestClass::Read),
    ];
    const IDENTITY_SHADOW_ROUTE_CLAIMS: &[RouteClaim] = &[RouteClaim::exact("/identity/users")];
    const IDENTITY_SHADOW_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[RouteSurfaceBinding::exact(
        "/identity/users",
        RouteSurface::Tenant,
        RouteRequestClass::Read,
    )];
    const CONSOLE_ROUTE_CLAIMS: &[RouteClaim] =
        &[RouteClaim::exact("/"), RouteClaim::prefix("/console")];
    const CONSOLE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        RouteSurfaceBinding::exact("/", RouteSurface::Tenant, RouteRequestClass::Read),
        tenant_prefix_safe("/console"),
        tenant_prefix_unsafe("/console"),
    ];
    const DATA_ROUTE_CLAIMS: &[RouteClaim] = &[RouteClaim::prefix("/data")];
    const DATA_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        tenant_prefix_safe("/data"),
        tenant_prefix_unsafe("/data"),
        RouteSurfaceBinding::exact_safe(
            "/data/backups/{backup_id}/storage-lineage",
            RouteSurface::Tenant,
            RouteRequestClass::OperatorRead,
        ),
        RouteSurfaceBinding::exact_safe(
            "/data/restores/{restore_id}/storage-lineage",
            RouteSurface::Tenant,
            RouteRequestClass::OperatorRead,
        ),
    ];
    const UVM_CONTROL_ROUTE_CLAIMS: &[RouteClaim] = &[
        RouteClaim::exact("/uvm"),
        RouteClaim::prefix("/uvm/templates"),
        RouteClaim::prefix("/uvm/instances"),
        RouteClaim::prefix("/uvm/migrations"),
    ];
    const UVM_CONTROL_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        RouteSurfaceBinding::exact("/uvm", RouteSurface::Tenant, RouteRequestClass::Read),
        RouteSurfaceBinding::prefix(
            "/uvm/templates",
            RouteSurface::Tenant,
            RouteRequestClass::Read,
        ),
        RouteSurfaceBinding::prefix(
            "/uvm/instances",
            RouteSurface::Tenant,
            RouteRequestClass::Read,
        ),
        RouteSurfaceBinding::prefix(
            "/uvm/migrations",
            RouteSurface::Tenant,
            RouteRequestClass::Read,
        ),
    ];
    const UVM_IMAGE_ROUTE_CLAIMS: &[RouteClaim] = &[
        RouteClaim::exact("/uvm/image"),
        RouteClaim::prefix("/uvm/images"),
    ];
    const UVM_IMAGE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        RouteSurfaceBinding::exact("/uvm/image", RouteSurface::Tenant, RouteRequestClass::Read),
        RouteSurfaceBinding::prefix("/uvm/images", RouteSurface::Tenant, RouteRequestClass::Read),
    ];
    const UVM_NODE_ROUTE_CLAIMS: &[RouteClaim] = &[
        RouteClaim::exact("/uvm/node"),
        RouteClaim::prefix("/uvm/runtime"),
    ];
    const UVM_NODE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        RouteSurfaceBinding::exact_safe(
            "/uvm/node",
            RouteSurface::Operator,
            RouteRequestClass::OperatorRead,
        ),
        operator_prefix_safe("/uvm/runtime"),
        operator_prefix_unsafe("/uvm/runtime"),
    ];
    const UVM_OBSERVE_ROUTE_CLAIMS: &[RouteClaim] = &[
        RouteClaim::exact("/uvm/observe"),
        RouteClaim::prefix("/uvm/perf-attestations"),
    ];
    const UVM_OBSERVE_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[
        RouteSurfaceBinding::exact_safe(
            "/uvm/observe",
            RouteSurface::Operator,
            RouteRequestClass::OperatorRead,
        ),
        operator_prefix_safe("/uvm/perf-attestations"),
        operator_prefix_unsafe("/uvm/perf-attestations"),
    ];
    const INTERNAL_ROUTE_CLAIMS: &[RouteClaim] = &[RouteClaim::prefix("/internal")];
    const INTERNAL_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[RouteSurfaceBinding::prefix(
        "/internal",
        RouteSurface::Internal,
        RouteRequestClass::Read,
    )];
    const IDEMPOTENT_ROUTE_CLAIMS: &[RouteClaim] = &[RouteClaim::exact("/idempotent")];
    const IDEMPOTENT_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[RouteSurfaceBinding::exact_unsafe(
        "/idempotent",
        RouteSurface::Tenant,
        RouteRequestClass::AsyncMutate,
    )];
    const STREAMING_ROUTE_CLAIMS: &[RouteClaim] = &[RouteClaim::exact("/streaming")];
    const STREAMING_ROUTE_SURFACES: &[RouteSurfaceBinding] = &[RouteSurfaceBinding::exact_safe(
        "/streaming",
        RouteSurface::Tenant,
        RouteRequestClass::Read,
    )];
    const INTERNAL_ROUTE_AUDIENCES: &[InternalRouteAudienceBinding] =
        &[InternalRouteAudienceBinding::prefix("/internal", "runtime")];
    const IDENTITY_INTERNAL_ROUTE_AUDIENCES: &[InternalRouteAudienceBinding] =
        &[InternalRouteAudienceBinding::prefix(
            "/identity",
            "identity",
        )];

    #[tokio::test]
    async fn special_routes_return_expected_json() {
        let runtime = PlatformRuntime::new(Vec::new()).unwrap_or_else(|error| panic!("{error}"));

        let healthz = runtime.special_response_for_path("/healthz").unwrap();
        assert_eq!(healthz.status(), StatusCode::OK);
        assert_eq!(
            healthz
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        let healthz_body = healthz.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(healthz_body.as_ref(), br#"{"status":"ok"}"#);

        let healthz_slash = runtime.special_response_for_path("/healthz/").unwrap();
        assert_eq!(healthz_slash.status(), StatusCode::OK);

        let readyz = runtime.special_response_for_path("/readyz").unwrap();
        assert_eq!(readyz.status(), StatusCode::SERVICE_UNAVAILABLE);
        let readyz_body = readyz.into_body().collect().await.unwrap().to_bytes();
        let readyz_json: serde_json::Value = serde_json::from_slice(&readyz_body).unwrap();
        assert_eq!(readyz_json["status"], "starting");
        assert_eq!(readyz_json["reason"], "process_state_unavailable");

        let readyz_slash = runtime.special_response_for_path("/readyz/").unwrap();
        assert_eq!(readyz_slash.status(), StatusCode::SERVICE_UNAVAILABLE);

        runtime.metrics.increment_counter("http.requests.total", 2);
        let metrics = runtime.special_response_for_path("/metrics").unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
        let metrics_body = metrics.into_body().collect().await.unwrap().to_bytes();
        let snapshot: uhost_core::MetricSnapshot = serde_json::from_slice(&metrics_body).unwrap();
        assert_eq!(snapshot.counters.get("http.requests.total"), Some(&2));

        let topology = runtime
            .special_response_for_path("/runtime/topology")
            .unwrap();
        assert_eq!(topology.status(), StatusCode::OK);
        let topology_body = topology.into_body().collect().await.unwrap().to_bytes();
        let topology_json: serde_json::Value = serde_json::from_slice(&topology_body).unwrap();
        assert_eq!(topology_json["process_role"], "all_in_one");
        assert_eq!(topology_json["deployment_mode"], "all_in_one");
        assert_eq!(topology_json["region"]["region_id"], "local");
        assert_eq!(topology_json["region"]["region_name"], "local");
        assert_eq!(topology_json["cell"]["cell_id"], "local:local-cell");
        assert_eq!(topology_json["cell"]["cell_name"], "local-cell");
        assert!(topology_json.get("process_state").is_none());
        assert_eq!(
            topology_json["service_groups"],
            serde_json::Value::Array(Vec::new())
        );
        assert_eq!(
            topology_json["service_group_directory"],
            serde_json::Value::Array(Vec::new())
        );
        assert_eq!(
            topology_json["participants"],
            serde_json::Value::Array(Vec::new())
        );
        assert_eq!(
            topology_json["tombstone_history"],
            serde_json::Value::Array(Vec::new())
        );

        let topology_slash = runtime
            .special_response_for_path("/runtime/topology/")
            .unwrap();
        assert_eq!(topology_slash.status(), StatusCode::OK);
    }

    #[test]
    fn special_routes_do_not_claim_other_paths() {
        let runtime = PlatformRuntime::new(Vec::new()).unwrap_or_else(|error| panic!("{error}"));

        assert!(runtime.special_response_for_path("/not-found").is_none());
    }

    #[test]
    fn runtime_topology_defaults_to_explicit_all_in_one_role() {
        let runtime = PlatformRuntime::new(Vec::new()).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            runtime.topology().process_role,
            RuntimeProcessRole::AllInOne
        );
        assert_eq!(runtime.topology().deployment_mode, ServiceMode::AllInOne);
        assert_eq!(runtime.topology().region.region_id, "local");
        assert_eq!(runtime.topology().region.region_name, "local");
        assert_eq!(runtime.topology().cell.cell_id, "local:local-cell");
        assert_eq!(runtime.topology().cell.cell_name, "local-cell");
        assert!(runtime.topology().process_state.is_none());
        assert!(runtime.topology().service_groups.is_empty());
        assert!(runtime.topology().service_group_directory.is_empty());
        assert!(runtime.topology().participants.is_empty());
        assert!(runtime.topology().tombstone_history.is_empty());
    }

    #[test]
    fn runtime_topology_handle_replaces_shared_snapshot() {
        let runtime = PlatformRuntime::new(Vec::new()).unwrap_or_else(|error| panic!("{error}"));
        let handle = runtime.topology_handle();

        handle.replace(
            RuntimeTopology::new(RuntimeProcessRole::Controller)
                .with_deployment_mode(ServiceMode::Distributed),
        );

        let snapshot = runtime.topology();
        assert_eq!(snapshot.process_role, RuntimeProcessRole::Controller);
        assert_eq!(snapshot.deployment_mode, ServiceMode::Distributed);
    }

    #[test]
    fn runtime_can_adopt_shared_topology_handle() {
        let shared = RuntimeTopologyHandle::new(RuntimeTopology::new(RuntimeProcessRole::Worker));
        let runtime = PlatformRuntime::new(Vec::new())
            .unwrap_or_else(|error| panic!("{error}"))
            .with_topology_handle(shared.clone());

        shared.replace(
            RuntimeTopology::new(RuntimeProcessRole::Controller)
                .with_deployment_mode(ServiceMode::Distributed),
        );

        assert_eq!(
            runtime.topology().process_role,
            RuntimeProcessRole::Controller
        );
        assert_eq!(runtime.topology().deployment_mode, ServiceMode::Distributed);
    }

    #[tokio::test]
    async fn readyz_returns_ok_for_fresh_serving_runtime_process() {
        let registered_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let renewed_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_005)
            .unwrap_or_else(|error| panic!("{error}"));
        let expires_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_020)
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime = PlatformRuntime::new(Vec::new())
            .unwrap_or_else(|error| panic!("{error}"))
            .with_topology(
                RuntimeTopology::new(RuntimeProcessRole::AllInOne).with_process_state(
                    RuntimeProcessState::new(
                        "all_in_one:runtime-node-a",
                        RuntimeReadinessState::Ready,
                        RuntimeDrainIntent::Serving,
                        registered_at,
                        RuntimeLeaseState::new(
                            renewed_at,
                            expires_at,
                            15,
                            RuntimeLeaseFreshness::Fresh,
                        ),
                    ),
                ),
            );

        let readyz = runtime.special_response_for_path("/readyz").unwrap();
        assert_eq!(readyz.status(), StatusCode::OK);
        let readyz_body = readyz.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(readyz_body.as_ref(), br#"{"status":"ready"}"#);
    }

    #[tokio::test]
    async fn readyz_reports_stale_lease_as_unready() {
        let registered_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let renewed_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_005)
            .unwrap_or_else(|error| panic!("{error}"));
        let expires_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_020)
            .unwrap_or_else(|error| panic!("{error}"));
        let runtime = PlatformRuntime::new(Vec::new())
            .unwrap_or_else(|error| panic!("{error}"))
            .with_topology(
                RuntimeTopology::new(RuntimeProcessRole::AllInOne).with_process_state(
                    RuntimeProcessState::new(
                        "all_in_one:runtime-node-a",
                        RuntimeReadinessState::Ready,
                        RuntimeDrainIntent::Serving,
                        registered_at,
                        RuntimeLeaseState::new(
                            renewed_at,
                            expires_at,
                            15,
                            RuntimeLeaseFreshness::Stale,
                        ),
                    ),
                ),
            );

        let readyz = runtime.special_response_for_path("/readyz").unwrap();
        assert_eq!(readyz.status(), StatusCode::SERVICE_UNAVAILABLE);
        let readyz_body = readyz.into_body().collect().await.unwrap().to_bytes();
        let readyz_json: serde_json::Value = serde_json::from_slice(&readyz_body).unwrap();
        assert_eq!(readyz_json["status"], "unready");
        assert_eq!(readyz_json["reason"], "lease_stale");
    }

    #[tokio::test]
    async fn readyz_fails_closed_when_runtime_failure_is_latched() {
        let registered_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let renewed_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_005)
            .unwrap_or_else(|error| panic!("{error}"));
        let expires_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_020)
            .unwrap_or_else(|error| panic!("{error}"));
        let readyz_handle = RuntimeReadyzHandle::default();
        readyz_handle.fail(
            RuntimeReadyzFailureReason::LeaseRenewalFailed,
            "failed to decode document collection",
        );
        let runtime = PlatformRuntime::new(Vec::new())
            .unwrap_or_else(|error| panic!("{error}"))
            .with_readyz_handle(readyz_handle)
            .with_topology(
                RuntimeTopology::new(RuntimeProcessRole::AllInOne).with_process_state(
                    RuntimeProcessState::new(
                        "all_in_one:runtime-node-a",
                        RuntimeReadinessState::Ready,
                        RuntimeDrainIntent::Serving,
                        registered_at,
                        RuntimeLeaseState::new(
                            renewed_at,
                            expires_at,
                            15,
                            RuntimeLeaseFreshness::Fresh,
                        ),
                    ),
                ),
            );

        let readyz = runtime.special_response_for_path("/readyz").unwrap();
        assert_eq!(readyz.status(), StatusCode::SERVICE_UNAVAILABLE);
        let readyz_body = readyz.into_body().collect().await.unwrap().to_bytes();
        let readyz_json: serde_json::Value = serde_json::from_slice(&readyz_body).unwrap();
        assert_eq!(readyz_json["status"], "unready");
        assert_eq!(readyz_json["reason"], "lease_renewal_failed");
        assert_eq!(
            readyz_json["detail"],
            "failed to decode document collection"
        );
    }

    #[test]
    fn html_response_sets_html_content_type() {
        let response = html_response(StatusCode::OK, "<p>hello</p>").unwrap();

        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
    }

    #[test]
    fn not_found_response_maps_to_404() {
        let response = PlatformRuntime::not_found_response("/missing");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn reserved_route_claim_is_rejected_at_startup() {
        let error = match PlatformRuntime::new(vec![registered_service(
            "colliding-service",
            COLLIDING_ROUTE_CLAIMS,
            COLLIDING_ROUTE_SURFACES,
        )]) {
            Ok(_) => panic!("reserved runtime claims must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(error.message.contains("reserved runtime route"));
    }

    #[test]
    fn reserved_runtime_topology_route_is_rejected_at_startup() {
        let error = match PlatformRuntime::new(vec![registered_service(
            "shadow-runtime-topology",
            TOPOLOGY_COLLIDING_ROUTE_CLAIMS,
            TOPOLOGY_COLLIDING_ROUTE_SURFACES,
        )]) {
            Ok(_) => panic!("reserved runtime topology route must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(error.message.contains("/runtime/topology"));
    }

    #[test]
    fn missing_route_surface_classification_is_rejected_at_startup() {
        let error = match PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            &[],
        )]) {
            Ok(_) => panic!("missing surface classification must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert!(error.message.contains("explicit surface classification"));
    }

    #[test]
    fn missing_internal_route_audience_is_rejected_at_startup() {
        let error = match PlatformRuntime::new(vec![registered_service(
            "internal",
            INTERNAL_ROUTE_CLAIMS,
            INTERNAL_ROUTE_SURFACES,
        )]) {
            Ok(_) => panic!("missing internal audience must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert!(error.message.contains("explicit internal audience"));
    }

    #[test]
    fn stray_internal_route_audience_is_rejected_at_startup() {
        let error = match PlatformRuntime::new(vec![registered_service_with_internal_audiences(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
            IDENTITY_INTERNAL_ROUTE_AUDIENCES,
        )]) {
            Ok(_) => panic!("non-internal routes must reject internal audiences"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert!(
            error
                .message
                .contains("must classify the route as internal")
        );
    }

    #[test]
    fn stray_route_surface_classification_is_rejected_at_startup() {
        let error = match PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_EXTRA_ROUTE_SURFACES,
        )]) {
            Ok(_) => panic!("stray surface classification must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::InvalidInput);
        assert!(
            error
                .message
                .contains("does not match an owned route claim")
        );
    }

    #[test]
    fn overlapping_route_claims_are_rejected_at_startup() {
        let error = match PlatformRuntime::new(vec![
            registered_service("identity", IDENTITY_ROUTE_CLAIMS, IDENTITY_ROUTE_SURFACES),
            registered_service(
                "identity-shadow",
                IDENTITY_SHADOW_ROUTE_CLAIMS,
                IDENTITY_SHADOW_ROUTE_SURFACES,
            ),
        ]) {
            Ok(_) => panic!("overlapping claims must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::Conflict);
        assert!(error.message.contains("overlaps service `identity`"));
    }

    #[test]
    fn route_registry_resolves_representative_paths() {
        let runtime = PlatformRuntime::new(vec![
            registered_service("console", CONSOLE_ROUTE_CLAIMS, CONSOLE_ROUTE_SURFACES),
            registered_service("identity", IDENTITY_ROUTE_CLAIMS, IDENTITY_ROUTE_SURFACES),
            registered_service(
                "uvm-control",
                UVM_CONTROL_ROUTE_CLAIMS,
                UVM_CONTROL_ROUTE_SURFACES,
            ),
            registered_service(
                "uvm-image",
                UVM_IMAGE_ROUTE_CLAIMS,
                UVM_IMAGE_ROUTE_SURFACES,
            ),
            registered_service("uvm-node", UVM_NODE_ROUTE_CLAIMS, UVM_NODE_ROUTE_SURFACES),
            registered_service(
                "uvm-observe",
                UVM_OBSERVE_ROUTE_CLAIMS,
                UVM_OBSERVE_ROUTE_SURFACES,
            ),
        ])
        .unwrap_or_else(|error| panic!("{error}"));

        let resolved_route = |path: &str| {
            runtime
                .resolve_request_path(path)
                .unwrap_or_else(|error| panic!("{error}"))
                .unwrap_or_else(|| panic!("missing owner for {path}"))
        };

        assert_eq!(resolved_route("/").service_name, "console");
        assert_eq!(resolved_route("/").surface, RouteSurface::Tenant);
        assert_eq!(resolved_route("/console/settings").service_name, "console");
        assert_eq!(resolved_route("/identity/users").service_name, "identity");
        assert_eq!(
            resolved_route("/identity/users").surface,
            RouteSurface::Tenant
        );
        assert_eq!(resolved_route("/uvm").service_name, "uvm-control");
        assert_eq!(resolved_route("/uvm/templates").service_name, "uvm-control");
        assert_eq!(resolved_route("/uvm/image").service_name, "uvm-image");
        assert_eq!(
            resolved_route("/uvm/images/firmware").service_name,
            "uvm-image"
        );
        assert_eq!(resolved_route("/uvm/node").service_name, "uvm-node");
        assert_eq!(resolved_route("/uvm/node").surface, RouteSurface::Operator);
        assert_eq!(
            resolved_route("/uvm/runtime/instances").service_name,
            "uvm-node"
        );
        assert_eq!(
            resolved_route("/uvm/runtime/instances").surface,
            RouteSurface::Operator
        );
        assert_eq!(resolved_route("/uvm/observe").service_name, "uvm-observe");
        assert_eq!(
            resolved_route("/uvm/observe").surface,
            RouteSurface::Operator
        );
        assert_eq!(
            resolved_route("/uvm/perf-attestations").service_name,
            "uvm-observe"
        );
        assert_eq!(
            resolved_route("/uvm/perf-attestations").surface,
            RouteSurface::Operator
        );
    }

    #[test]
    fn route_registry_prefers_parameterized_exact_paths_over_prefix_claims() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "data",
            DATA_ROUTE_CLAIMS,
            DATA_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"));

        let backup_lineage = runtime
            .resolve_request_path("/data/backups/backup_123/storage-lineage")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing backup-lineage route"));
        assert_eq!(backup_lineage.service_name, "data");
        assert_eq!(backup_lineage.surface, RouteSurface::Tenant);
        assert_eq!(
            backup_lineage.request_class,
            RouteRequestClass::OperatorRead
        );
        assert_eq!(
            backup_lineage.claim.path(),
            "/data/backups/{backup_id}/storage-lineage"
        );

        let restore_lineage = runtime
            .resolve_request_path("/data/restores/restore_123/storage-lineage")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing restore-lineage route"));
        assert_eq!(restore_lineage.service_name, "data");
        assert_eq!(restore_lineage.surface, RouteSurface::Tenant);
        assert_eq!(
            restore_lineage.request_class,
            RouteRequestClass::OperatorRead
        );
        assert_eq!(
            restore_lineage.claim.path(),
            "/data/restores/{restore_id}/storage-lineage"
        );
    }

    #[test]
    fn route_registry_resolves_forwarded_paths() {
        let runtime = PlatformRuntime::new_with_forwarded_services(
            vec![registered_service(
                "console",
                CONSOLE_ROUTE_CLAIMS,
                CONSOLE_ROUTE_SURFACES,
            )],
            vec![ForwardedServiceRegistration::new(
                "identity",
                FORWARDED_IDENTITY_ROUTE_SURFACES,
            )],
        )
        .unwrap_or_else(|error| panic!("{error}"));

        let forwarded_root = runtime
            .resolve_request_path("/identity")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing forwarded route"));
        assert_eq!(forwarded_root.service_name, "identity");
        assert_eq!(forwarded_root.surface, RouteSurface::Tenant);

        let forwarded = runtime
            .resolve_request_path("/identity/users")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing forwarded route"));
        assert_eq!(forwarded.service_name, "identity");
        assert_eq!(forwarded.surface, RouteSurface::Tenant);
        assert_eq!(
            forwarded.forwarded_route(),
            Some(ForwardedRoute::new("identity", RouteSurface::Tenant))
        );
        assert!(forwarded.local_service_index().is_none());
    }

    #[test]
    fn auth_gate_enforces_operator_request_class_on_parameterized_exact_paths() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "data",
            DATA_ROUTE_CLAIMS,
            DATA_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token"))
                .with_bearer_token_authorizer(std::sync::Arc::new(StubBearerTokenAuthorizer::new(
                    "workload-token",
                    "data",
                    PrincipalIdentity::new(PrincipalKind::Workload, "svc:data-runner")
                        .with_credential_id("wid_data_runner"),
                ))),
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer workload-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request_with_method(
                &headers,
                &Method::GET,
                "/data/backups/backup_123/storage-lineage",
                &mut context,
            )
            .expect_err("operator-bound lineage paths must reject workload principals");
        assert_eq!(error.code, ErrorCode::Forbidden);
        assert_eq!(
            error.message,
            "route request class `operator_read` requires operator principal"
        );
        assert_eq!(context.actor.as_deref(), Some("svc:data-runner"));
        let principal = context
            .principal
            .clone()
            .unwrap_or_else(|| panic!("missing workload principal"));
        assert_eq!(principal.kind, PrincipalKind::Workload);

        let mut operator_headers = HeaderMap::new();
        operator_headers.insert(
            AUTHORIZATION,
            "Bearer bootstrap-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut operator_context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request_with_method(
                &operator_headers,
                &Method::GET,
                "/data/restores/restore_123/storage-lineage",
                &mut operator_context,
            )
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(operator_context.actor.as_deref(), Some("bootstrap_admin"));
        let operator_principal = operator_context
            .principal
            .clone()
            .unwrap_or_else(|| panic!("missing bootstrap operator principal"));
        assert_eq!(operator_principal.kind, PrincipalKind::Operator);
    }

    #[test]
    fn reserved_runtime_routes_have_explicit_surfaces() {
        let runtime = PlatformRuntime::new(Vec::new()).unwrap_or_else(|error| panic!("{error}"));

        let healthz = runtime
            .resolve_request_path("/healthz/")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reserved runtime route"));
        assert_eq!(healthz.service_name, RUNTIME_SERVICE_NAME);
        assert_eq!(healthz.surface, RouteSurface::Public);

        let readyz = runtime
            .resolve_request_path("/readyz")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reserved runtime route"));
        assert_eq!(readyz.service_name, RUNTIME_SERVICE_NAME);
        assert_eq!(readyz.surface, RouteSurface::Public);

        let metrics = runtime
            .resolve_request_path("/metrics")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing reserved runtime route"));
        assert_eq!(metrics.service_name, RUNTIME_SERVICE_NAME);
        assert_eq!(metrics.surface, RouteSurface::Operator);

        let topology = runtime
            .resolve_request_path("/runtime/topology/")
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing runtime topology route"));
        assert_eq!(topology.service_name, RUNTIME_SERVICE_NAME);
        assert_eq!(topology.surface, RouteSurface::Operator);
    }

    #[tokio::test]
    async fn runtime_topology_response_reflects_configured_service_group_ownership() {
        let registered_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap_or_else(|error| panic!("{error}"));
        let renewed_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_005)
            .unwrap_or_else(|error| panic!("{error}"));
        let expires_at = time::OffsetDateTime::from_unix_timestamp(1_700_000_020)
            .unwrap_or_else(|error| panic!("{error}"));
        let topology = RuntimeTopology::new(RuntimeProcessRole::AllInOne)
            .with_deployment_mode(ServiceMode::Distributed)
            .with_node_name("runtime-node-a")
            .with_region_membership(RuntimeRegionMembership::new("us-east-1", "us-east-1"))
            .with_cell_membership(RuntimeCellMembership::new(
                "us-east-1:control-a",
                "control-a",
            ))
            .with_process_state(RuntimeProcessState::new(
                "all_in_one:runtime-node-a",
                RuntimeReadinessState::Ready,
                RuntimeDrainIntent::Serving,
                registered_at,
                RuntimeLeaseState::new(renewed_at, expires_at, 15, RuntimeLeaseFreshness::Fresh),
            ))
            .with_participants([
                RuntimeParticipantRegistration::new(
                    "all_in_one:runtime-node-a",
                    "runtime_process",
                    "all_in_one:runtime-node-a",
                    "all_in_one",
                    registered_at,
                )
                .with_node_name("runtime-node-a")
                .with_service_groups(["edge", "uvm"])
                .with_lease_registration_id("all_in_one:runtime-node-a")
                .with_state(RuntimeParticipantState::new(
                    RuntimeReadinessState::Ready,
                    RuntimeDrainIntent::Serving,
                    RuntimeLeaseState::new(renewed_at, expires_at, 15, RuntimeLeaseFreshness::Fresh),
                )
                .with_lease_source(RuntimeParticipantLeaseSource::LinkedRegistration)),
                RuntimeParticipantRegistration::new(
                    "controller:runtime-node-b",
                    "runtime_process",
                    "controller:runtime-node-b",
                    "controller",
                    registered_at,
                )
                .with_node_name("runtime-node-b")
                .with_service_groups(["control"])
                .with_lease_registration_id("controller:runtime-node-b")
                .with_state(RuntimeParticipantState::new(
                    RuntimeReadinessState::Ready,
                    RuntimeDrainIntent::Draining,
                    RuntimeLeaseState::new(
                        registered_at,
                        registered_at,
                        15,
                        RuntimeLeaseFreshness::Expired,
                    ),
                )
                .with_lease_source(RuntimeParticipantLeaseSource::LinkedRegistration)
                .with_published_drain_intent(RuntimeDrainIntent::Serving))
                .with_reconciliation(
                    RuntimeParticipantReconciliation::new(expires_at)
                        .with_stale_since(registered_at)
                        .with_cleanup_workflow(RuntimeParticipantCleanupWorkflow::new(
                            "stale-participant-cleanup:us-east-1:control-a:controller:runtime-node-b",
                            "runtime.participant.cleanup.v1",
                            "running",
                            RuntimeParticipantCleanupStage::TombstoneEligible,
                            3,
                            renewed_at,
                            registered_at,
                            renewed_at,
                        )
                        .with_preflight_confirmed_at(expires_at)
                        .with_route_withdrawal(RuntimeEvacuationRouteWithdrawalArtifact::new(
                            "route-withdrawal:us-east-1:control-a:controller:runtime-node-b",
                            "controller:runtime-node-b",
                            vec![String::from("control")],
                            expires_at,
                        ))
                        .with_target_readiness(RuntimeEvacuationTargetReadinessArtifact::new(
                            "target-readiness:us-east-1:control-a:controller:runtime-node-b:all_in_one:runtime-node-a",
                            "controller:runtime-node-b",
                            "all_in_one:runtime-node-a",
                            vec![String::from("control")],
                            expires_at,
                        ))
                        .with_rollback(RuntimeEvacuationRollbackArtifact::new(
                            "rollback:us-east-1:control-a:controller:runtime-node-b:all_in_one:runtime-node-a",
                            "controller:runtime-node-b",
                            "all_in_one:runtime-node-a",
                            vec![String::from("control")],
                            expires_at,
                        ))
                        .with_tombstone_eligible_at(renewed_at)),
                ),
            ])
            .with_service_group(
                RuntimeLogicalServiceGroup::Edge,
                RuntimeProcessRole::AllInOne,
                ["console", "dns", "ingress"],
            )
            .with_service_group(
                RuntimeLogicalServiceGroup::Uvm,
                RuntimeProcessRole::AllInOne,
                ["uvm-control", "uvm-node"],
            )
            .with_service_group_directory([
                RuntimeServiceGroupDirectoryEntry::new(RuntimeLogicalServiceGroup::Edge)
                    .with_resolved_registration_ids(["all_in_one:runtime-node-a"])
                    .with_conflict_state(RuntimeServiceGroupConflictState::NoConflict)
                    .with_registrations([
                        RuntimeServiceGroupRegistrationResolution::new(
                            "all_in_one:runtime-node-a",
                            "runtime_process",
                            "all_in_one:runtime-node-a",
                            "all_in_one",
                            registered_at,
                            true,
                        )
                        .with_node_name("runtime-node-a")
                        .with_lease_registration_id("all_in_one:runtime-node-a")
                        .with_readiness(RuntimeReadinessState::Ready)
                        .with_drain_intent(RuntimeDrainIntent::Serving)
                        .with_lease_freshness(RuntimeLeaseFreshness::Fresh),
                    ]),
                RuntimeServiceGroupDirectoryEntry::new(RuntimeLogicalServiceGroup::Control)
                    .with_resolved_registration_ids(["all_in_one:runtime-node-a"])
                    .with_conflict_state(RuntimeServiceGroupConflictState::NoConflict)
                    .with_registrations([
                        RuntimeServiceGroupRegistrationResolution::new(
                            "all_in_one:runtime-node-a",
                            "runtime_process",
                            "all_in_one:runtime-node-a",
                            "all_in_one",
                            registered_at,
                            true,
                        )
                        .with_node_name("runtime-node-a")
                        .with_lease_registration_id("all_in_one:runtime-node-a")
                        .with_readiness(RuntimeReadinessState::Ready)
                        .with_drain_intent(RuntimeDrainIntent::Serving)
                        .with_lease_freshness(RuntimeLeaseFreshness::Fresh),
                        RuntimeServiceGroupRegistrationResolution::new(
                            "controller:runtime-node-b",
                            "runtime_process",
                            "controller:runtime-node-b",
                            "controller",
                            registered_at,
                            false,
                        )
                        .with_node_name("runtime-node-b")
                        .with_lease_registration_id("controller:runtime-node-b")
                        .with_readiness(RuntimeReadinessState::Ready)
                        .with_drain_intent(RuntimeDrainIntent::Draining)
                        .with_lease_freshness(RuntimeLeaseFreshness::Expired),
                    ]),
            ]);
        let runtime = PlatformRuntime::new(Vec::new())
            .unwrap_or_else(|error| panic!("{error}"))
            .with_topology(topology);

        let response = runtime
            .special_response_for_path("/runtime/topology")
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let process_state = payload
            .get("process_state")
            .unwrap_or_else(|| panic!("missing process_state object"));
        let service_groups = payload["service_groups"]
            .as_array()
            .unwrap_or_else(|| panic!("missing service_groups array"));
        let service_group_directory = payload["service_group_directory"]
            .as_array()
            .unwrap_or_else(|| panic!("missing service_group_directory array"));
        let participants = payload["participants"]
            .as_array()
            .unwrap_or_else(|| panic!("missing participants array"));
        let edge = service_groups
            .iter()
            .find(|group| group["group"] == "edge")
            .unwrap_or_else(|| panic!("missing edge group"));
        let uvm = service_groups
            .iter()
            .find(|group| group["group"] == "uvm")
            .unwrap_or_else(|| panic!("missing uvm group"));
        let participant = participants
            .iter()
            .find(|participant| participant["registration_id"] == "all_in_one:runtime-node-a")
            .unwrap_or_else(|| panic!("missing runtime participant"));
        let edge_directory = service_group_directory
            .iter()
            .find(|entry| entry["group"] == "edge")
            .unwrap_or_else(|| panic!("missing edge service-group directory"));
        let control_directory = service_group_directory
            .iter()
            .find(|entry| entry["group"] == "control")
            .unwrap_or_else(|| panic!("missing control service-group directory"));
        let stale_participant = participants
            .iter()
            .find(|participant| participant["registration_id"] == "controller:runtime-node-b")
            .unwrap_or_else(|| panic!("missing stale runtime participant"));

        assert_eq!(payload["process_role"], "all_in_one");
        assert_eq!(payload["deployment_mode"], "distributed");
        assert_eq!(payload["node_name"], "runtime-node-a");
        assert_eq!(payload["region"]["region_id"], "us-east-1");
        assert_eq!(payload["region"]["region_name"], "us-east-1");
        assert_eq!(payload["cell"]["cell_id"], "us-east-1:control-a");
        assert_eq!(payload["cell"]["cell_name"], "control-a");
        assert_eq!(
            process_state["registration_id"],
            "all_in_one:runtime-node-a"
        );
        assert_eq!(process_state["readiness"], "ready");
        assert_eq!(process_state["drain_intent"], "serving");
        assert_eq!(process_state["lease"]["duration_seconds"], 15);
        assert_eq!(process_state["lease"]["freshness"], "fresh");
        assert_eq!(participant["participant_kind"], "runtime_process");
        assert_eq!(participant["subject_id"], "all_in_one:runtime-node-a");
        assert_eq!(participant["role"], "all_in_one");
        assert_eq!(participant["node_name"], "runtime-node-a");
        assert_eq!(
            participant["lease_registration_id"],
            "all_in_one:runtime-node-a"
        );
        let participant_state = participant
            .get("state")
            .unwrap_or_else(|| panic!("missing participant state object"));
        assert!(participant.get("reconciliation").is_none());
        assert_eq!(participant_state["readiness"], "ready");
        assert_eq!(participant_state["drain_intent"], "serving");
        assert_eq!(participant_state["published_drain_intent"], "serving");
        assert!(participant_state.get("degraded_reason").is_none());
        assert_eq!(participant_state["lease_source"], "linked_registration");
        assert_eq!(participant_state["lease"]["duration_seconds"], 15);
        assert_eq!(participant_state["lease"]["freshness"], "fresh");
        assert_eq!(
            participant["service_groups"],
            serde_json::json!(["edge", "uvm"])
        );
        assert_eq!(
            edge_directory["resolved_registration_ids"],
            serde_json::json!(["all_in_one:runtime-node-a"])
        );
        assert_eq!(edge_directory["conflict_state"], "no_conflict");
        assert_eq!(control_directory["conflict_state"], "no_conflict");
        assert_eq!(
            control_directory["registrations"][1]["drain_intent"],
            "draining"
        );
        assert_eq!(
            control_directory["registrations"][1]["lease_freshness"],
            "expired"
        );
        assert_eq!(control_directory["registrations"][1]["healthy"], false);
        let stale_participant_state = stale_participant
            .get("state")
            .unwrap_or_else(|| panic!("missing stale participant state object"));
        let stale_participant_reconciliation = stale_participant
            .get("reconciliation")
            .unwrap_or_else(|| panic!("missing stale participant reconciliation object"));
        let cleanup_workflow = stale_participant_reconciliation
            .get("cleanup_workflow")
            .unwrap_or_else(|| panic!("missing stale participant cleanup workflow object"));
        assert_eq!(stale_participant_state["drain_intent"], "draining");
        assert_eq!(stale_participant_state["published_drain_intent"], "serving");
        assert_eq!(stale_participant_state["degraded_reason"], "lease_expired");
        assert_eq!(
            stale_participant_state["lease_source"],
            "linked_registration"
        );
        assert_eq!(stale_participant_state["lease"]["freshness"], "expired");
        assert_eq!(
            stale_participant_reconciliation["stale_since"],
            serde_json::json!(registered_at)
        );
        assert_eq!(
            stale_participant_reconciliation["last_reconciled_at"],
            serde_json::json!(expires_at)
        );
        assert_eq!(
            cleanup_workflow["id"],
            "stale-participant-cleanup:us-east-1:control-a:controller:runtime-node-b"
        );
        assert_eq!(
            cleanup_workflow["workflow_kind"],
            "runtime.participant.cleanup.v1"
        );
        assert_eq!(cleanup_workflow["phase"], "running");
        assert_eq!(cleanup_workflow["stage"], "tombstone_eligible");
        assert_eq!(
            cleanup_workflow["review_observations"],
            serde_json::json!(3)
        );
        assert_eq!(
            cleanup_workflow["last_observed_stale_at"],
            serde_json::json!(renewed_at)
        );
        assert_eq!(
            cleanup_workflow["preflight_confirmed_at"],
            serde_json::json!(expires_at)
        );
        assert_eq!(
            cleanup_workflow["route_withdrawal"]["source_participant_registration_id"],
            "controller:runtime-node-b"
        );
        assert_eq!(
            cleanup_workflow["route_withdrawal"]["service_groups"],
            serde_json::json!(["control"])
        );
        assert_eq!(
            cleanup_workflow["route_withdrawal"]["prepared_at"],
            serde_json::json!(expires_at)
        );
        assert_eq!(
            cleanup_workflow["target_readiness"]["source_participant_registration_id"],
            "controller:runtime-node-b"
        );
        assert_eq!(
            cleanup_workflow["target_readiness"]["target_participant_registration_id"],
            "all_in_one:runtime-node-a"
        );
        assert_eq!(
            cleanup_workflow["target_readiness"]["service_groups"],
            serde_json::json!(["control"])
        );
        assert_eq!(
            cleanup_workflow["target_readiness"]["prepared_at"],
            serde_json::json!(expires_at)
        );
        assert_eq!(
            cleanup_workflow["rollback"]["source_participant_registration_id"],
            "controller:runtime-node-b"
        );
        assert_eq!(
            cleanup_workflow["rollback"]["target_participant_registration_id"],
            "all_in_one:runtime-node-a"
        );
        assert_eq!(
            cleanup_workflow["rollback"]["service_groups"],
            serde_json::json!(["control"])
        );
        assert_eq!(
            cleanup_workflow["rollback"]["prepared_at"],
            serde_json::json!(expires_at)
        );
        assert_eq!(
            cleanup_workflow["tombstone_eligible_at"],
            serde_json::json!(renewed_at)
        );
        assert_eq!(edge["owner_role"], "all_in_one");
        assert_eq!(
            edge["services"],
            serde_json::json!(["console", "dns", "ingress"])
        );
        assert_eq!(uvm["owner_role"], "all_in_one");
        assert_eq!(
            uvm["services"],
            serde_json::json!(["uvm-control", "uvm-node"])
        );
    }

    #[test]
    fn canonicalize_path_rejects_dot_dot_segments() {
        let error = PlatformRuntime::canonicalize_path("/console/../metrics").unwrap_err();

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[test]
    fn canonicalize_path_collapses_redundant_slashes() {
        let path = PlatformRuntime::canonicalize_path("/console//status/").unwrap();

        assert_eq!(path.as_ref(), "/console/status/");
    }

    #[test]
    fn auth_gate_allows_public_route_without_token() {
        let runtime = PlatformRuntime::new(Vec::new())
            .unwrap_or_else(|error| panic!("{error}"))
            .with_access_config(
                RuntimeAccessConfig::default()
                    .with_bootstrap_admin_token(SecretString::new("bootstrap-token")),
            );
        let headers = HeaderMap::new();
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request(&headers, "/healthz", &mut context)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(context.actor.is_none());

        let mut slash_context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        runtime
            .authorize_request(&headers, "/healthz/", &mut slash_context)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(slash_context.actor.is_none());

        let mut readyz_context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        runtime
            .authorize_request(&headers, "/readyz", &mut readyz_context)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(readyz_context.actor.is_none());
    }

    #[test]
    fn auth_gate_denies_service_route_without_explicit_dev_access_when_token_missing() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"));
        let headers = HeaderMap::new();
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .expect_err("service routes should default to protected access");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn auth_gate_allows_service_route_with_explicit_local_dev_access() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_unauthenticated_local_dev_service_routes(),
        );
        let headers = HeaderMap::new();
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(context.actor.is_none());
    }

    #[test]
    fn auth_gate_local_dev_fallback_does_not_open_metrics() {
        let runtime = PlatformRuntime::new(Vec::new())
            .unwrap_or_else(|error| panic!("{error}"))
            .with_access_config(
                RuntimeAccessConfig::default().with_unauthenticated_local_dev_service_routes(),
            );
        let headers = HeaderMap::new();
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/metrics", &mut context)
            .expect_err("metrics should remain protected without a bootstrap token");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn auth_gate_denies_service_route_without_presented_token() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token")),
        );
        let headers = HeaderMap::new();
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .expect_err("private routes should require bootstrap token auth");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn auth_gate_accepts_authorization_bearer_token() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token")),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer bootstrap-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(context.actor.as_deref(), Some("bootstrap_admin"));
    }

    #[test]
    fn auth_gate_accepts_custom_bootstrap_token_header() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token")),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-uhost-admin-token",
            "bootstrap-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(context.actor.as_deref(), Some("bootstrap_admin"));
    }

    #[test]
    fn auth_gate_accepts_workload_bearer_token_on_tenant_service_route() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token"))
                .with_bearer_token_authorizer(std::sync::Arc::new(StubBearerTokenAuthorizer::new(
                    "workload-token",
                    "identity",
                    PrincipalIdentity::new(PrincipalKind::Workload, "svc:build-runner")
                        .with_credential_id("wid_runtime_test"),
                ))),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer workload-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .unwrap_or_else(|error| panic!("{error}"));

        let principal = context
            .principal
            .clone()
            .unwrap_or_else(|| panic!("missing workload principal"));
        assert_eq!(principal.kind, PrincipalKind::Workload);
        assert_eq!(principal.subject, "svc:build-runner");
        assert_eq!(principal.credential_id.as_deref(), Some("wid_runtime_test"));
        assert_eq!(context.actor.as_deref(), Some("svc:build-runner"));
    }

    #[test]
    fn auth_gate_rejects_unmatched_workload_bearer_token_on_tenant_service_route() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token"))
                .with_bearer_token_authorizer(std::sync::Arc::new(StubBearerTokenAuthorizer::new(
                    "workload-token",
                    "identity",
                    PrincipalIdentity::new(PrincipalKind::Workload, "svc:build-runner")
                        .with_credential_id("wid_runtime_test"),
                ))),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer mismatched-workload-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .expect_err("unmatched workload tokens must be rejected");
        assert_eq!(error.code, ErrorCode::Unauthorized);
        assert!(context.actor.is_none());
        assert!(context.principal.is_none());
    }

    #[test]
    fn auth_gate_accepts_workload_bearer_token_on_forwarded_tenant_service_route() {
        let runtime = PlatformRuntime::new_with_forwarded_services(
            Vec::new(),
            vec![ForwardedServiceRegistration::new(
                "identity",
                IDENTITY_ROUTE_SURFACES,
            )],
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token"))
                .with_bearer_token_authorizer(std::sync::Arc::new(StubBearerTokenAuthorizer::new(
                    "workload-token",
                    "identity",
                    PrincipalIdentity::new(PrincipalKind::Workload, "svc:build-runner")
                        .with_credential_id("wid_runtime_test"),
                ))),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer workload-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .unwrap_or_else(|error| panic!("{error}"));

        let principal = context
            .principal
            .clone()
            .unwrap_or_else(|| panic!("missing workload principal"));
        assert_eq!(principal.kind, PrincipalKind::Workload);
        assert_eq!(principal.subject, "svc:build-runner");
        assert_eq!(principal.credential_id.as_deref(), Some("wid_runtime_test"));
        assert_eq!(context.actor.as_deref(), Some("svc:build-runner"));
    }

    #[test]
    fn auth_gate_workload_bearer_token_does_not_open_operator_surface() {
        let runtime = PlatformRuntime::new(vec![registered_service(
            "identity",
            IDENTITY_ROUTE_CLAIMS,
            IDENTITY_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token"))
                .with_bearer_token_authorizer(std::sync::Arc::new(StubBearerTokenAuthorizer::new(
                    "workload-token",
                    "identity",
                    PrincipalIdentity::new(PrincipalKind::Workload, "svc:build-runner")
                        .with_credential_id("wid_runtime_test"),
                ))),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer workload-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/metrics", &mut context)
            .expect_err("operator routes must remain bootstrap-gated");
        assert_eq!(error.code, ErrorCode::Unauthorized);
        assert!(context.actor.is_none());
        assert!(context.principal.is_none());
    }

    #[test]
    fn auth_gate_internal_surface_ignores_local_dev_fallback() {
        let runtime = PlatformRuntime::new(vec![registered_service_with_internal_audiences(
            "internal",
            INTERNAL_ROUTE_CLAIMS,
            INTERNAL_ROUTE_SURFACES,
            INTERNAL_ROUTE_AUDIENCES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_unauthenticated_local_dev_service_routes(),
        );
        let headers = HeaderMap::new();
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/internal/status", &mut context)
            .expect_err("internal routes should remain protected even in local dev mode");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn auth_gate_local_dev_fallback_does_not_open_forwarded_tenant_route() {
        let runtime = PlatformRuntime::new_with_forwarded_services(
            Vec::new(),
            vec![ForwardedServiceRegistration::new(
                "identity",
                IDENTITY_ROUTE_SURFACES,
            )],
        )
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_unauthenticated_local_dev_service_routes(),
        );
        let headers = HeaderMap::new();
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/identity/users", &mut context)
            .expect_err("forwarded routes should remain protected even in local dev mode");
        assert_eq!(error.code, ErrorCode::Unauthorized);
    }

    #[test]
    fn auth_gate_internal_surface_accepts_matching_service_identity() {
        let runtime = PlatformRuntime::new(vec![registered_service_with_internal_audiences(
            "internal",
            INTERNAL_ROUTE_CLAIMS,
            INTERNAL_ROUTE_SURFACES,
            INTERNAL_ROUTE_AUDIENCES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_bearer_token_authorizer(std::sync::Arc::new(
                StubBearerTokenAuthorizer::new(
                    "runtime-token",
                    "runtime",
                    PrincipalIdentity::new(PrincipalKind::Workload, "svc:runtime-peer")
                        .with_credential_id("wid_runtime_peer"),
                ),
            )),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer runtime-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        runtime
            .authorize_request(&headers, "/internal/status", &mut context)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(context.actor.as_deref(), Some("svc:runtime-peer"));
        let principal = context
            .principal
            .clone()
            .unwrap_or_else(|| panic!("missing internal route principal"));
        assert_eq!(principal.kind, PrincipalKind::Workload);
        assert_eq!(principal.subject, "svc:runtime-peer");
    }

    #[test]
    fn auth_gate_internal_surface_rejects_bootstrap_token() {
        let runtime = PlatformRuntime::new(vec![registered_service_with_internal_audiences(
            "internal",
            INTERNAL_ROUTE_CLAIMS,
            INTERNAL_ROUTE_SURFACES,
            INTERNAL_ROUTE_AUDIENCES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default()
                .with_bootstrap_admin_token(SecretString::new("bootstrap-token")),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer bootstrap-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/internal/status", &mut context)
            .expect_err("internal routes should not accept bootstrap auth");
        assert_eq!(error.code, ErrorCode::Unauthorized);
        assert!(context.actor.is_none());
        assert!(context.principal.is_none());
    }

    #[test]
    fn auth_gate_internal_surface_rejects_non_service_identity_principal() {
        let runtime = PlatformRuntime::new(vec![registered_service_with_internal_audiences(
            "internal",
            INTERNAL_ROUTE_CLAIMS,
            INTERNAL_ROUTE_SURFACES,
            INTERNAL_ROUTE_AUDIENCES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_bearer_token_authorizer(std::sync::Arc::new(
                StubBearerTokenAuthorizer::new(
                    "runtime-token",
                    "runtime",
                    PrincipalIdentity::new(PrincipalKind::User, "user:alice")
                        .with_credential_id("api_key_123"),
                ),
            )),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer runtime-token"
                .parse()
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let error = runtime
            .authorize_request(&headers, "/internal/status", &mut context)
            .expect_err("internal routes should require service identities");
        assert_eq!(error.code, ErrorCode::Unauthorized);
        assert!(context.actor.is_none());
        assert!(context.principal.is_none());
    }

    #[test]
    fn runtime_uses_default_network_limits() {
        let runtime = PlatformRuntime::new(Vec::new()).unwrap_or_else(|error| panic!("{error}"));
        let (max_active_connections, timeout) = runtime.connection_limits();

        assert_eq!(max_active_connections, 16_384);
        assert_eq!(timeout, Duration::from_secs(30));
    }

    #[test]
    fn runtime_clamps_zero_connection_limit() {
        let runtime =
            PlatformRuntime::new_with_network_limits(Vec::new(), 0, Duration::from_secs(0))
                .unwrap_or_else(|error| panic!("{error}"));
        let (max_active_connections, timeout) = runtime.connection_limits();

        assert_eq!(max_active_connections, 1);
        assert_eq!(timeout, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn idempotent_post_replays_persisted_response_across_runtime_restart() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = temp.path().join("http-idempotency.json");

        let first_counter = Arc::new(AtomicUsize::new(0));
        let first_runtime = runtime_with_idempotent_service(
            first_counter.clone(),
            HttpIdempotencyJournal::open(&journal_path)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let first = first_runtime
            .dispatch(idempotent_request("POST", "/idempotent", b"alpha", "idem-1").await)
            .await;
        let first_status = first.status();
        let first_body = first
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();

        assert_eq!(first_status, StatusCode::CREATED);
        assert_eq!(first_counter.load(Ordering::SeqCst), 1);

        let second_counter = Arc::new(AtomicUsize::new(0));
        let second_runtime = runtime_with_idempotent_service(
            second_counter.clone(),
            HttpIdempotencyJournal::open(&journal_path)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );
        let second = second_runtime
            .dispatch(idempotent_request("POST", "/idempotent", b"alpha", "idem-1").await)
            .await;
        let second_status = second.status();
        let second_body = second
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();

        assert_eq!(second_status, StatusCode::CREATED);
        assert_eq!(second_body, first_body);
        assert_eq!(second_counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn idempotent_post_rejects_key_reuse_for_different_request_digest() {
        let temp = tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = temp.path().join("http-idempotency.json");
        let counter = Arc::new(AtomicUsize::new(0));
        let runtime = runtime_with_idempotent_service(
            counter.clone(),
            HttpIdempotencyJournal::open(&journal_path)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
        );

        let created = runtime
            .dispatch(idempotent_request("POST", "/idempotent", b"alpha", "idem-1").await)
            .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        let conflict = runtime
            .dispatch(idempotent_request("POST", "/idempotent", b"beta", "idem-1").await)
            .await;
        let conflict_status = conflict.status();
        let conflict_body = conflict
            .into_body()
            .collect()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .to_bytes();
        let payload: serde_json::Value =
            serde_json::from_slice(&conflict_body).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(conflict_status, StatusCode::CONFLICT);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            payload["error"]["message"].as_str(),
            Some("idempotency key already used for different request")
        );
    }

    #[tokio::test]
    async fn dispatch_preserves_streaming_service_response_frames() {
        let runtime = PlatformRuntime::new(vec![ServiceRegistration::new(
            Arc::new(StreamingResponseService),
            STREAMING_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_unauthenticated_local_dev_service_routes(),
        );
        let request = Request::builder()
            .method(Method::GET)
            .uri("/streaming")
            .body(make_incoming_with_body(b"").await)
            .unwrap_or_else(|error| panic!("{error}"));

        let response = runtime.dispatch(request).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/octet-stream")
        );

        let mut body = response.into_body();
        let first = next_body_chunk(&mut body).await;
        let second = next_body_chunk(&mut body).await;
        assert_eq!(first.as_ref(), b"hello ");
        assert_eq!(second.as_ref(), b"world");
        assert!(
            body.frame().await.is_none(),
            "runtime should preserve the streaming service body instead of rebuilding one full response body"
        );
    }

    #[derive(Debug)]
    struct ClaimedService {
        name: &'static str,
        claims: &'static [RouteClaim],
    }

    #[derive(Debug)]
    struct IdempotentEchoService {
        calls: Arc<AtomicUsize>,
    }

    #[derive(Debug)]
    struct StreamingResponseService;

    #[derive(Debug)]
    struct MultiChunkBody {
        chunks: VecDeque<Bytes>,
    }

    impl MultiChunkBody {
        fn new(chunks: impl IntoIterator<Item = Bytes>) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
            }
        }
    }

    impl Body for MultiChunkBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Ready(self.chunks.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    #[derive(Debug)]
    struct StubBearerTokenAuthorizer {
        allowed_token: &'static str,
        allowed_audience: &'static str,
        principal: PrincipalIdentity,
    }

    impl StubBearerTokenAuthorizer {
        fn new(
            allowed_token: &'static str,
            allowed_audience: &'static str,
            principal: PrincipalIdentity,
        ) -> Self {
            Self {
                allowed_token,
                allowed_audience,
                principal,
            }
        }
    }

    impl BearerTokenAuthorizer for StubBearerTokenAuthorizer {
        fn authorize<'a>(
            &'a self,
            bearer_token: &'a str,
            audience: &'a str,
        ) -> AuthorizationFuture<'a> {
            Box::pin(async move {
                if bearer_token == self.allowed_token && audience == self.allowed_audience {
                    return Ok(Some(self.principal.clone()));
                }

                Ok(None)
            })
        }
    }

    fn runtime_with_idempotent_service(
        counter: Arc<AtomicUsize>,
        journal: HttpIdempotencyJournal,
    ) -> PlatformRuntime {
        PlatformRuntime::new(vec![ServiceRegistration::new(
            Arc::new(IdempotentEchoService { calls: counter }),
            IDEMPOTENT_ROUTE_SURFACES,
        )])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_access_config(
            RuntimeAccessConfig::default().with_unauthenticated_local_dev_service_routes(),
        )
        .with_idempotency_journal(journal)
    }

    async fn idempotent_request(
        method: &str,
        path: &str,
        body: &[u8],
        idempotency_key: &str,
    ) -> Request<Incoming> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("Idempotency-Key", idempotency_key)
            .body(make_incoming_with_body(body).await)
            .unwrap_or_else(|error| panic!("{error}"))
    }

    async fn make_incoming_with_body(bytes: &[u8]) -> Incoming {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let address = listener
            .local_addr()
            .unwrap_or_else(|error| panic!("{error}"));
        let payload = bytes.to_vec();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            let response_head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            stream
                .write_all(response_head.as_bytes())
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            stream
                .write_all(&payload)
                .await
                .unwrap_or_else(|error| panic!("{error}"));
            stream
                .shutdown()
                .await
                .unwrap_or_else(|error| panic!("{error}"));
        });

        let stream = tokio::net::TcpStream::connect(address)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = http::Request::builder()
            .method("GET")
            .uri("/payload")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap_or_else(|error| panic!("{error}"));
        let response = sender
            .send_request(request)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        server.await.unwrap_or_else(|error| panic!("{error}"));
        response.into_body()
    }

    fn registered_service(
        name: &'static str,
        claims: &'static [RouteClaim],
        route_surfaces: &'static [RouteSurfaceBinding],
    ) -> ServiceRegistration {
        registered_service_with_internal_audiences(name, claims, route_surfaces, &[])
    }

    fn registered_service_with_internal_audiences(
        name: &'static str,
        claims: &'static [RouteClaim],
        route_surfaces: &'static [RouteSurfaceBinding],
        internal_route_audiences: &'static [InternalRouteAudienceBinding],
    ) -> ServiceRegistration {
        ServiceRegistration::new_with_internal_route_audiences(
            std::sync::Arc::new(ClaimedService { name, claims }),
            route_surfaces,
            internal_route_audiences,
        )
    }

    impl HttpService for ClaimedService {
        fn name(&self) -> &'static str {
            self.name
        }

        fn route_claims(&self) -> &'static [RouteClaim] {
            self.claims
        }

        fn handle<'a>(
            &'a self,
            _request: ServiceRequest,
            _context: RequestContext,
        ) -> ResponseFuture<'a> {
            Box::pin(async move { Ok(None) })
        }
    }

    impl HttpService for IdempotentEchoService {
        fn name(&self) -> &'static str {
            "idempotent-echo"
        }

        fn route_claims(&self) -> &'static [RouteClaim] {
            IDEMPOTENT_ROUTE_CLAIMS
        }

        fn handle<'a>(
            &'a self,
            request: ServiceRequest,
            _context: RequestContext,
        ) -> ResponseFuture<'a> {
            Box::pin(async move {
                let body = uhost_api::read_body(request)
                    .await
                    .unwrap_or_else(|error| panic!("{error}"));
                let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                let payload = serde_json::json!({
                    "call": call,
                    "body": String::from_utf8(body.to_vec())
                        .unwrap_or_else(|error| panic!("{error}")),
                });
                json_response(StatusCode::CREATED, &payload).map(Some)
            })
        }
    }

    impl HttpService for StreamingResponseService {
        fn name(&self) -> &'static str {
            "streaming-response"
        }

        fn route_claims(&self) -> &'static [RouteClaim] {
            STREAMING_ROUTE_CLAIMS
        }

        fn handle<'a>(
            &'a self,
            _request: ServiceRequest,
            _context: RequestContext,
        ) -> ResponseFuture<'a> {
            Box::pin(async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/octet-stream")
                    .body(box_body(MultiChunkBody::new([
                        Bytes::from_static(b"hello "),
                        Bytes::from_static(b"world"),
                    ])))
                    .map(Some)
                    .map_err(|error| {
                        PlatformError::new(
                            ErrorCode::Internal,
                            "failed to build streaming runtime test response",
                        )
                        .with_detail(error.to_string())
                    })
            })
        }
    }

    async fn next_body_chunk(body: &mut ApiBody) -> Bytes {
        match body.frame().await {
            Some(Ok(frame)) => frame
                .into_data()
                .unwrap_or_else(|_| panic!("expected one data frame")),
            Some(Err(error)) => panic!("{error}"),
            None => panic!("expected another response chunk"),
        }
    }
}
