//! UVM image management service.
//!
//! This bounded context owns image ingest, verification, promotion, and
//! compatibility reporting for UVM guests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use http::{Method, Request, StatusCode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uhost_api::{ApiBody, json_response, parse_json, path_segments};
use uhost_core::{PlatformError, RequestContext, Result, sha256_hex};
use uhost_runtime::{HttpService, ResponseFuture};
use uhost_store::{
    AuditLog, DocumentStore, DurableOutbox, MetadataCollection, OutboxMessage, StoredDocument,
};
use uhost_types::{
    AuditActor, AuditId, EventHeader, EventPayload, OwnershipScope, PlatformEvent,
    ResourceMetadata, ServiceEvent, UvmCompatibilityReportId, UvmFirmwareBundleId,
    UvmGuestProfileId, UvmImageId, UvmOverlayPolicyId, UvmRegionCellPolicyId,
};
use uhost_uvm::{
    BootDevice, BootPath, ClaimTier, GuestArchitecture, GuestProfile, HostClass, MachineFamily,
    UvmCompatibilityEvidence, UvmCompatibilityEvidenceSource, UvmCompatibilityRequirement,
    UvmExecutionIntent,
};

/// Stable attestation kinds persisted alongside UVM artifact metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UvmArtifactAttestationKind {
    /// Signature validation evidence for the artifact.
    Signature,
    /// Provenance or build-lineage evidence for the artifact.
    Provenance,
}

impl UvmArtifactAttestationKind {
    /// Return the stable string form used across persisted records and contracts.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::Provenance => "provenance",
        }
    }
}

/// Persisted attestation evidence attached to one UVM artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmArtifactAttestationRecord {
    /// Attestation classification.
    pub kind: UvmArtifactAttestationKind,
    /// Opaque reference, bundle identifier, or URI for the attestation payload.
    pub reference: String,
    /// Timestamp when this attestation was accepted into durable state.
    pub recorded_at: OffsetDateTime,
}

/// UVM image metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmImageRecord {
    /// Image identifier.
    pub id: UvmImageId,
    /// Source format kind.
    pub source_kind: String,
    /// Source location.
    pub source_uri: String,
    /// Guest OS family.
    pub guest_os: String,
    /// Guest architecture.
    pub architecture: String,
    /// Derived guest profile for execution and compatibility planning.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Explicit guest-profile artifact selection when provided.
    #[serde(default)]
    pub guest_profile_id: Option<UvmGuestProfileId>,
    /// Derived machine family for execution planning.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    // Whether this image is intended to be mounted as install media.
    #[serde(default)]
    pub install_media: bool,
    // Preferred initial boot device derived from the imported media shape.
    #[serde(default = "default_boot_device_key")]
    pub preferred_boot_device: String,
    /// Explicit overlay-policy artifact selection when provided.
    #[serde(default)]
    pub overlay_policy_id: Option<UvmOverlayPolicyId>,
    /// Content digest.
    pub digest: String,
    /// Whether digest + policy verification passed.
    pub verified: bool,
    /// Persisted signature and provenance evidence accepted for this image.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<UvmArtifactAttestationRecord>,
    /// Legacy single-channel summary derived from publication manifests.
    ///
    /// Publication manifests remain the authoritative promotion state; this
    /// field exists only as a compatibility summary when every manifest shares
    /// one channel.
    pub promoted_channel: Option<String>,
    /// Audit-linked publication manifests keyed by image/channel/host_class/machine_family/guest_profile/region/cell.
    #[serde(default)]
    pub publication_manifests: Vec<UvmImagePublicationManifest>,
    /// Legal guardrail policy status.
    pub legal_policy: String,
    /// Evidence-gated claim tier attached to this image contract.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Execution intent emitted for downstream node portability decisions.
    #[serde(default)]
    pub execution_intent: UvmExecutionIntent,
    /// Shared compatibility requirement emitted for downstream node admission.
    #[serde(default)]
    pub compatibility_requirement: Option<UvmCompatibilityRequirement>,
    /// Evidence rows explaining the compatibility requirement.
    #[serde(default)]
    pub compatibility_evidence: Vec<UvmCompatibilityEvidence>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
    #[serde(default, skip_serializing, rename = "signature_verified")]
    legacy_signature_verified: bool,
    #[serde(default, skip_serializing, rename = "provenance_verified")]
    legacy_provenance_verified: bool,
}

/// Audit-linked publication manifest for an image variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmImagePublicationManifest {
    /// Publication channel.
    pub channel: String,
    /// Shared host-class key for publication scoping.
    #[serde(default = "default_host_class_key")]
    pub host_class: String,
    /// Machine-family key locked to the image contract for now.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    /// Guest-profile key locked to the image contract for now.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Region scope for this publication manifest.
    #[serde(default = "default_region_key")]
    pub region: String,
    /// Cell scope for this publication manifest.
    #[serde(default = "default_cell_key")]
    pub cell: String,
    /// Exact compatibility-row identifier used to gate this publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_row_id: Option<UvmCompatibilityReportId>,
    /// Stable exact-match key derived from the promoted image tuple and publication scope.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compatibility_match_key: String,
    /// Host family copied from the matched compatibility row.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_family: String,
    /// Accelerator backend copied from the matched compatibility row.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub accelerator_backend: String,
    /// Claim tier copied from the matched compatibility row.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claim_tier: String,
    /// Whether the matched row supports secure boot.
    #[serde(default)]
    pub secure_boot_supported: bool,
    /// Whether the matched row supports live migration.
    #[serde(default)]
    pub live_migration_supported: bool,
    /// Whether the matched row was policy-approved.
    #[serde(default)]
    pub policy_approved: bool,
    /// Notes copied from the matched compatibility row.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compatibility_notes: String,
    /// Audit event that published or backfilled this manifest.
    pub audit_event_id: AuditId,
    /// Time the manifest was published.
    pub published_at: OffsetDateTime,
}

/// Compatibility matrix row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmCompatibilityReport {
    /// Compatibility row identifier.
    pub id: UvmCompatibilityReportId,
    /// Host-class key used to scope publication and admission decisions.
    #[serde(default)]
    pub host_class: String,
    /// Region scope for this compatibility row.
    #[serde(default = "default_region_key")]
    pub region: String,
    /// Cell scope for this compatibility row.
    #[serde(default = "default_cell_key")]
    pub cell: String,
    /// Host OS family.
    pub host_family: String,
    /// Guest architecture.
    pub guest_architecture: String,
    /// Accelerator backend.
    pub accelerator_backend: String,
    /// Machine family associated with this compatibility row.
    #[serde(default = "default_machine_family_key")]
    pub machine_family: String,
    /// Guest profile associated with this compatibility row.
    #[serde(default = "default_guest_profile_key")]
    pub guest_profile: String,
    /// Whether secure boot is supported.
    pub secure_boot_supported: bool,
    /// Whether live migration is supported.
    pub live_migration_supported: bool,
    /// Whether this pair passes current legal/policy checks.
    pub policy_approved: bool,
    /// Highest allowed claim tier for this row.
    #[serde(default = "default_claim_tier_key")]
    pub claim_tier: String,
    /// Operator notes.
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UvmCompatibilityReportRevision {
    variant_key: String,
    revision: u64,
    active_version: u64,
    report: UvmCompatibilityReport,
}

#[derive(Debug, Clone)]
struct CompatibilityRowCandidate {
    key: String,
    version: u64,
    updated_at: OffsetDateTime,
    variant_key: String,
    row: UvmCompatibilityReport,
}

/// One signer entry in a persisted firmware trust chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmFirmwareSignerLineageEntry {
    /// Role played by this signer in the firmware trust chain.
    pub role: String,
    /// Human-readable signer identity or fingerprint label.
    pub signer: String,
    /// Upstream issuer for the signer when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// Firmware bundle metadata owned by the UVM image plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmFirmwareBundleRecord {
    /// Firmware bundle identifier.
    pub id: UvmFirmwareBundleId,
    /// Human-readable bundle name.
    pub name: String,
    /// Target guest architecture.
    pub architecture: String,
    /// Firmware profile key.
    pub firmware_profile: String,
    /// Storage reference for the bundle artifact.
    pub artifact_uri: String,
    /// Whether the bundle can satisfy secure-boot requirements.
    pub secure_boot_capable: bool,
    /// Whether the bundle has been verified.
    pub verified: bool,
    /// Explicit secure-boot posture for this firmware-policy artifact.
    #[serde(default)]
    pub secure_boot_posture: String,
    /// Ordered signer lineage for the firmware trust chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signer_lineage: Vec<UvmFirmwareSignerLineageEntry>,
    /// Monotonic policy revision for the firmware artifact.
    #[serde(default = "default_firmware_policy_revision")]
    pub policy_revision: u32,
    /// Persisted signature and provenance evidence accepted for this bundle.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<UvmArtifactAttestationRecord>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Explicit guest-profile artifact owned by the UVM image plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmGuestProfileRecord {
    /// Guest-profile identifier.
    pub id: UvmGuestProfileId,
    /// Human-readable profile name.
    pub name: String,
    /// Guest-profile key from the shared UVM contract.
    pub guest_profile: String,
    /// Target guest architecture.
    pub architecture: String,
    /// Machine family selected by this profile.
    pub machine_family: String,
    /// Boot path selected by this profile.
    pub boot_path: String,
    /// Firmware bundle selected by this profile when present.
    pub firmware_bundle_id: Option<UvmFirmwareBundleId>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Compatibility rules that govern where an overlay chain may attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmOverlayChainCompatibilityRules {
    /// Base image source kinds that may attach the overlay chain.
    #[serde(default = "default_overlay_chain_base_source_kinds")]
    pub base_source_kinds: Vec<String>,
    /// Machine families that may consume the overlay chain.
    #[serde(default = "default_overlay_chain_machine_families")]
    pub machine_families: Vec<String>,
    /// Guest profiles that may consume the overlay chain.
    #[serde(default = "default_overlay_chain_guest_profiles")]
    pub guest_profiles: Vec<String>,
}

impl Default for UvmOverlayChainCompatibilityRules {
    fn default() -> Self {
        Self {
            base_source_kinds: default_overlay_chain_base_source_kinds(),
            machine_families: default_overlay_chain_machine_families(),
            guest_profiles: default_overlay_chain_guest_profiles(),
        }
    }
}

/// Publication rules that govern where overlay-backed images may be promoted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmOverlayPublicationRules {
    /// Promotion channels allowed when the image references this overlay policy.
    #[serde(default = "default_overlay_publication_channels")]
    pub allowed_channels: Vec<String>,
    /// Optional host-class restrictions. An empty list means any host class.
    #[serde(default)]
    pub allowed_host_classes: Vec<String>,
    /// Optional region restrictions. An empty list means any region.
    #[serde(default)]
    pub allowed_regions: Vec<String>,
    /// Optional cell restrictions. An empty list means any cell.
    #[serde(default)]
    pub allowed_cells: Vec<String>,
}

impl Default for UvmOverlayPublicationRules {
    fn default() -> Self {
        Self {
            allowed_channels: default_overlay_publication_channels(),
            allowed_host_classes: Vec::new(),
            allowed_regions: Vec::new(),
            allowed_cells: Vec::new(),
        }
    }
}

/// Overlay-policy artifact owned by the UVM image plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmOverlayPolicyRecord {
    /// Overlay-policy identifier.
    pub id: UvmOverlayPolicyId,
    /// Human-readable policy name.
    pub name: String,
    /// Root mode for the base image.
    pub root_mode: String,
    /// Maximum writable layers allowed by the policy.
    pub writable_layer_limit: u8,
    /// Whether template cloning is explicitly allowed.
    pub template_clone_enabled: bool,
    /// Compatibility constraints for overlay-chain attachment.
    #[serde(default)]
    pub chain_compatibility: UvmOverlayChainCompatibilityRules,
    /// Publication rules for overlay-backed image promotions.
    #[serde(default)]
    pub publication: UvmOverlayPublicationRules,
    /// Persisted signature and provenance evidence accepted for this policy artifact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<UvmArtifactAttestationRecord>,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

/// Region/cell variant policy owned by the UVM image plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmRegionCellPolicyRecord {
    /// Variant-policy identifier.
    pub id: UvmRegionCellPolicyId,
    /// Human-readable policy name.
    pub name: String,
    /// Region governed by this policy.
    pub region: String,
    /// Optional cell-specific override within the region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell: Option<String>,
    /// Environment posture represented by this policy.
    pub policy_mode: String,
    /// Whether compatible artifacts must stay local to the governed perimeter.
    #[serde(default)]
    pub require_local_artifacts: bool,
    /// Allowed fallback regions when the local region cannot satisfy placement.
    #[serde(default)]
    pub fallback_regions: Vec<String>,
    /// Allowed fallback cells when the local cell cannot satisfy placement.
    #[serde(default)]
    pub fallback_cells: Vec<String>,
    /// Operator rationale and operational notes.
    pub notes: String,
    /// Shared metadata.
    pub metadata: ResourceMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UvmImagesSummaryResponse {
    pub total_images: usize,
    pub verified_images: usize,
    pub unverified_images: usize,
    pub signature_verified_images: usize,
    pub provenance_verified_images: usize,
    pub artifact_verified_images: usize,
    pub total_firmware_bundles: usize,
    pub verified_firmware_bundles: usize,
    pub total_guest_profiles: usize,
    pub total_overlay_policies: usize,
    pub total_region_cell_policies: usize,
    pub architecture_counts: BTreeMap<String, usize>,
    pub source_kind_counts: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ImportImageRequest {
    source_kind: String,
    source_uri: String,
    guest_os: String,
    architecture: String,
    digest: Option<String>,
    signature_attestation: Option<String>,
    provenance_attestation: Option<String>,
    license_token: Option<String>,
    guest_profile_id: Option<String>,
    overlay_policy_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifyImageRequest {
    expected_digest: Option<String>,
    require_signature: Option<bool>,
    require_provenance: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PromoteImageRequest {
    channel: String,
    #[serde(default)]
    host_class: Option<String>,
    #[serde(default)]
    machine_family: Option<String>,
    #[serde(default)]
    guest_profile: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    cell: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateFirmwareBundleRequest {
    name: String,
    architecture: String,
    firmware_profile: String,
    artifact_uri: String,
    secure_boot_capable: Option<bool>,
    verified: Option<bool>,
    secure_boot_posture: Option<String>,
    #[serde(default)]
    signer_lineage: Vec<CreateFirmwareSignerLineageEntryRequest>,
    signature_attestation: Option<String>,
    provenance_attestation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateFirmwareSignerLineageEntryRequest {
    role: String,
    signer: String,
    issuer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateGuestProfileRequest {
    name: String,
    guest_profile: String,
    architecture: String,
    machine_family: String,
    boot_path: String,
    firmware_bundle_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateOverlayPolicyRequest {
    name: String,
    root_mode: String,
    writable_layer_limit: Option<u8>,
    template_clone_enabled: Option<bool>,
    chain_compatibility: Option<UvmOverlayChainCompatibilityRules>,
    publication: Option<UvmOverlayPublicationRules>,
    signature_attestation: Option<String>,
    provenance_attestation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CreateRegionCellPolicyRequest {
    name: String,
    region: String,
    cell: Option<String>,
    policy_mode: String,
    require_local_artifacts: Option<bool>,
    fallback_regions: Option<Vec<String>>,
    fallback_cells: Option<Vec<String>>,
    notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicationManifestSelection {
    channel: String,
    host_class: String,
    machine_family: String,
    guest_profile: String,
    region: String,
    cell: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactPublicationMatch {
    manifest: PublicationManifestSelection,
    row: UvmCompatibilityReport,
    compatibility_match_key: String,
}

/// UVM image service.
#[derive(Debug, Clone)]
pub struct UvmImageService {
    images: DocumentStore<UvmImageRecord>,
    compatibility: DocumentStore<UvmCompatibilityReport>,
    compatibility_revisions: MetadataCollection<UvmCompatibilityReportRevision>,
    firmware_bundles: DocumentStore<UvmFirmwareBundleRecord>,
    guest_profiles: DocumentStore<UvmGuestProfileRecord>,
    overlay_policies: DocumentStore<UvmOverlayPolicyRecord>,
    region_cell_policies: DocumentStore<UvmRegionCellPolicyRecord>,
    audit_log: AuditLog,
    outbox: DurableOutbox<PlatformEvent>,
    state_root: PathBuf,
}

const PUBLICATION_MANIFEST_MIGRATOR_ACTOR: &str = "system:uvm-image-publication-migrator";

impl UvmImageService {
    /// Open UVM image state.
    pub async fn open(state_root: impl AsRef<Path>) -> Result<Self> {
        let root = state_root.as_ref().join("uvm-image");
        let service = Self {
            images: DocumentStore::open(root.join("images.json")).await?,
            compatibility: DocumentStore::open(root.join("compatibility.json")).await?,
            compatibility_revisions: MetadataCollection::open_local(
                root.join("compatibility_revisions.json"),
            )
            .await?,
            firmware_bundles: DocumentStore::open(root.join("firmware_bundles.json")).await?,
            guest_profiles: DocumentStore::open(root.join("guest_profiles.json")).await?,
            overlay_policies: DocumentStore::open(root.join("overlay_policies.json")).await?,
            region_cell_policies: DocumentStore::open(root.join("region_cell_policies.json"))
                .await?,
            audit_log: AuditLog::open(root.join("audit.log")).await?,
            outbox: DurableOutbox::open(root.join("outbox.json")).await?,
            state_root: root,
        };
        service.upgrade_attestation_records().await?;
        service.ensure_default_compatibility().await?;
        service.enforce_compatibility_integrity().await?;
        service.refresh_scoped_compatibility_artifacts().await?;
        service.upgrade_publication_manifests().await?;
        service.enforce_firmware_policy_integrity().await?;
        Ok(service)
    }

    async fn upgrade_publication_manifests(&self) -> Result<()> {
        let context = publication_manifest_migration_context()?;
        for (key, stored) in self.images.list().await? {
            if stored.deleted {
                continue;
            }
            let mut record = stored.value;
            let backfilled = self
                .backfill_legacy_publication_manifests(key.as_str(), &mut record, &context)
                .await?;
            let normalized = normalize_publication_manifest_state(&mut record);
            if backfilled || normalized {
                record
                    .metadata
                    .touch(publication_manifest_state_fingerprint(
                        key.as_str(),
                        &record.publication_manifests,
                    ));
                self.images
                    .upsert(key.as_str(), record, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn refresh_scoped_compatibility_artifacts(&self) -> Result<()> {
        let mut image_rows = self.images.list().await?;
        image_rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in image_rows {
            if stored.deleted {
                continue;
            }
            let mut record = stored.value;
            let overlay_policy = if let Some(overlay_policy_id) = record.overlay_policy_id.as_ref()
            {
                Some(
                    self.load_overlay_policy(overlay_policy_id.as_str())
                        .await?
                        .value,
                )
            } else {
                None
            };
            let refreshed = self
                .build_image_compatibility_artifacts(&record, overlay_policy.as_ref())
                .await?;
            if refreshed != record.compatibility_evidence {
                record.compatibility_evidence = refreshed;
                record
                    .metadata
                    .touch(compatibility_evidence_state_fingerprint(
                        key.as_str(),
                        &record.compatibility_evidence,
                    ));
                self.images
                    .upsert(key.as_str(), record, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn build_image_compatibility_artifacts(
        &self,
        record: &UvmImageRecord,
        overlay_policy: Option<&UvmOverlayPolicyRecord>,
    ) -> Result<Vec<UvmCompatibilityEvidence>> {
        let requirement = match record.compatibility_requirement.as_ref() {
            Some(requirement) => requirement.clone(),
            None => build_image_compatibility_requirement(
                &record.architecture,
                &record.machine_family,
                &record.guest_profile,
                &record.preferred_boot_device,
                &record.claim_tier,
            )?,
        };
        let mut evidence = build_image_compatibility_evidence(
            &record.source_kind,
            &record.guest_os,
            &requirement,
            overlay_policy,
        );
        evidence.extend(self.list_scoped_compatibility_artifacts(record).await?);
        Ok(evidence)
    }

    async fn list_scoped_compatibility_artifacts(
        &self,
        record: &UvmImageRecord,
    ) -> Result<Vec<UvmCompatibilityEvidence>> {
        let mut rows = self
            .compatibility
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| normalize_compatibility_row(&stored.value))
            .collect::<Result<Vec<_>>>()?;
        rows.retain(|row| {
            row.guest_architecture == record.architecture
                && row.machine_family == record.machine_family
                && row.guest_profile == record.guest_profile
                && row.claim_tier == record.claim_tier
        });
        rows.sort_by(compare_compatibility_rows);
        Ok(rows
            .into_iter()
            .map(|row| UvmCompatibilityEvidence {
                source: UvmCompatibilityEvidenceSource::ImageContract,
                summary: compatibility_artifact_summary(&row),
                evidence_mode: Some(if row.policy_approved {
                    String::from("policy_approved")
                } else {
                    String::from("policy_blocked")
                }),
            })
            .collect())
    }

    async fn create_firmware_bundle(
        &self,
        request: CreateFirmwareBundleRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let CreateFirmwareBundleRequest {
            name,
            architecture,
            firmware_profile,
            artifact_uri,
            secure_boot_capable,
            verified,
            secure_boot_posture,
            signer_lineage,
            signature_attestation,
            provenance_attestation,
        } = request;
        let name = normalize_record_name(&name, "name")?;
        let architecture = normalize_architecture(&architecture)?;
        let firmware_profile = normalize_firmware_profile(&firmware_profile)?;
        let artifact_uri = normalize_source_uri(&artifact_uri)?;
        let secure_boot_capable = secure_boot_capable.unwrap_or(false);
        let verified = verified.unwrap_or(false);
        let attestations =
            build_attestation_records(signature_attestation, provenance_attestation)?;
        let signer_lineage = signer_lineage
            .into_iter()
            .map(|entry| UvmFirmwareSignerLineageEntry {
                role: entry.role,
                signer: entry.signer,
                issuer: entry.issuer,
            })
            .collect::<Vec<_>>();
        let (secure_boot_posture, signer_lineage) = normalize_firmware_policy_fields(
            &firmware_profile,
            secure_boot_capable,
            secure_boot_posture.as_deref(),
            signer_lineage,
        )?;

        let id = UvmFirmwareBundleId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate firmware bundle id")
                .with_detail(error.to_string())
        })?;
        let record = UvmFirmwareBundleRecord {
            id: id.clone(),
            name,
            architecture,
            firmware_profile,
            artifact_uri,
            secure_boot_capable,
            verified,
            secure_boot_posture,
            signer_lineage,
            policy_revision: default_firmware_policy_revision(),
            attestations,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.firmware_bundles
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.image.firmware_bundle.created.v1",
            "uvm_firmware_bundle",
            id.as_str(),
            "created",
            serde_json::json!({
                "architecture": record.architecture,
                "firmware_profile": record.firmware_profile,
                "secure_boot_posture": record.secure_boot_posture,
                "policy_revision": record.policy_revision,
                "signer_lineage_depth": record.signer_lineage.len(),
                "attestation_kinds": attestation_kind_keys(&record.attestations),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_guest_profile(
        &self,
        request: CreateGuestProfileRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let name = normalize_record_name(&request.name, "name")?;
        let guest_profile = normalize_guest_profile(&request.guest_profile)?;
        let architecture = normalize_architecture(&request.architecture)?;
        let machine_family = normalize_machine_family(&request.machine_family)?;
        let boot_path = normalize_boot_path(&request.boot_path)?;
        let firmware_bundle_id = request
            .firmware_bundle_id
            .map(|value| {
                UvmFirmwareBundleId::parse(value).map_err(|error| {
                    PlatformError::invalid("invalid firmware_bundle_id")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;
        if let Some(firmware_bundle_id) = firmware_bundle_id.as_ref() {
            let stored = self
                .firmware_bundles
                .get(firmware_bundle_id.as_str())
                .await?
                .ok_or_else(|| PlatformError::not_found("firmware bundle does not exist"))?;
            if stored.deleted {
                return Err(PlatformError::not_found("firmware bundle does not exist"));
            }
            if stored.value.architecture != architecture {
                return Err(PlatformError::conflict(
                    "firmware bundle architecture does not match guest profile architecture",
                ));
            }
        }

        let id = UvmGuestProfileId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate guest profile id")
                .with_detail(error.to_string())
        })?;
        let record = UvmGuestProfileRecord {
            id: id.clone(),
            name,
            guest_profile,
            architecture,
            machine_family,
            boot_path,
            firmware_bundle_id,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.guest_profiles
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.image.guest_profile.created.v1",
            "uvm_guest_profile",
            id.as_str(),
            "created",
            serde_json::json!({
                "guest_profile": record.guest_profile,
                "machine_family": record.machine_family,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_overlay_policy(
        &self,
        request: CreateOverlayPolicyRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let name = normalize_record_name(&request.name, "name")?;
        let root_mode = normalize_root_mode(&request.root_mode)?;
        let writable_layer_limit = request.writable_layer_limit.unwrap_or(1);
        if writable_layer_limit == 0 {
            return Err(PlatformError::invalid(
                "writable_layer_limit must be greater than zero",
            ));
        }
        let template_clone_enabled = request.template_clone_enabled.unwrap_or(true);
        let chain_compatibility =
            normalize_overlay_chain_compatibility(request.chain_compatibility)?;
        let publication = normalize_overlay_publication_rules(request.publication)?;
        let attestations = build_attestation_records(
            request.signature_attestation,
            request.provenance_attestation,
        )?;

        let id = UvmOverlayPolicyId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate overlay policy id")
                .with_detail(error.to_string())
        })?;
        let record = UvmOverlayPolicyRecord {
            id: id.clone(),
            name,
            root_mode,
            writable_layer_limit,
            template_clone_enabled,
            chain_compatibility,
            publication,
            attestations,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.overlay_policies
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.image.overlay_policy.created.v1",
            "uvm_overlay_policy",
            id.as_str(),
            "created",
            serde_json::json!({
                "root_mode": record.root_mode,
                "writable_layer_limit": record.writable_layer_limit,
                "base_source_kinds": record.chain_compatibility.base_source_kinds,
                "allowed_channels": record.publication.allowed_channels,
                "attestation_kinds": attestation_kind_keys(&record.attestations),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn create_region_cell_policy(
        &self,
        request: CreateRegionCellPolicyRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let name = normalize_record_name(&request.name, "name")?;
        let region = normalize_publication_scope(&request.region, "region")?;
        let cell = request
            .cell
            .map(|value| normalize_publication_scope(&value, "cell"))
            .transpose()?;
        let policy_mode = normalize_region_cell_policy_mode(&request.policy_mode)?;
        let require_local_artifacts = request
            .require_local_artifacts
            .unwrap_or(policy_mode == "sovereign");
        if policy_mode == "sovereign" && !require_local_artifacts {
            return Err(PlatformError::invalid(
                "sovereign region/cell policies must require local artifacts",
            ));
        }
        let fallback_regions = normalize_region_cell_policy_scopes(
            request.fallback_regions.unwrap_or_default(),
            "fallback_regions",
        )?;
        let fallback_cells = normalize_region_cell_policy_scopes(
            request.fallback_cells.unwrap_or_default(),
            "fallback_cells",
        )?;
        let notes = normalize_region_cell_policy_notes(&request.notes)?;

        let id = UvmRegionCellPolicyId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate region/cell policy id")
                .with_detail(error.to_string())
        })?;
        let record = UvmRegionCellPolicyRecord {
            id: id.clone(),
            name,
            region,
            cell,
            policy_mode,
            require_local_artifacts,
            fallback_regions,
            fallback_cells,
            notes,
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
        };
        self.region_cell_policies
            .create(id.as_str(), record.clone())
            .await?;
        self.append_event(
            "uvm.image.region_cell_policy.created.v1",
            "uvm_region_cell_policy",
            id.as_str(),
            "created",
            serde_json::json!({
                "region": record.region,
                "cell": record.cell,
                "policy_mode": record.policy_mode,
                "require_local_artifacts": record.require_local_artifacts,
                "fallback_regions": record.fallback_regions,
                "fallback_cells": record.fallback_cells,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn import_image(
        &self,
        request: ImportImageRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let source_kind = normalize_source_kind(&request.source_kind)?;
        let source_uri = normalize_source_uri(&request.source_uri)?;
        let guest_os = normalize_guest_os(&request.guest_os)?;
        let architecture = normalize_architecture(&request.architecture)?;
        let digest =
            normalize_digest(request.digest)?.unwrap_or_else(|| sha256_hex(source_uri.as_bytes()));
        let incoming_attestations = build_attestation_records(
            request.signature_attestation,
            request.provenance_attestation,
        )?;
        enforce_guest_image_guardrails(&guest_os, &architecture)?;
        let guest_profile_id = request
            .guest_profile_id
            .map(|value| {
                UvmGuestProfileId::parse(value).map_err(|error| {
                    PlatformError::invalid("invalid guest_profile_id")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;
        let overlay_policy_id = request
            .overlay_policy_id
            .map(|value| {
                UvmOverlayPolicyId::parse(value).map_err(|error| {
                    PlatformError::invalid("invalid overlay_policy_id")
                        .with_detail(error.to_string())
                })
            })
            .transpose()?;
        let (guest_profile, machine_family, guest_profile_id) =
            if let Some(guest_profile_id) = guest_profile_id {
                let stored = self
                    .guest_profiles
                    .get(guest_profile_id.as_str())
                    .await?
                    .ok_or_else(|| PlatformError::not_found("guest profile does not exist"))?;
                if stored.deleted {
                    return Err(PlatformError::not_found("guest profile does not exist"));
                }
                let profile = stored.value;
                if profile.architecture != architecture {
                    return Err(PlatformError::conflict(
                        "guest profile architecture does not match image architecture",
                    ));
                }
                if !guest_profile_supports_guest_os(&profile.guest_profile, &guest_os) {
                    return Err(PlatformError::conflict(
                        "guest profile is not compatible with guest_os",
                    ));
                }
                (
                    profile.guest_profile.clone(),
                    profile.machine_family.clone(),
                    Some(profile.id),
                )
            } else {
                (
                    default_guest_profile_for_guest_os(&guest_os),
                    default_machine_family_for_guest(&architecture, &guest_os),
                    None,
                )
            };
        let overlay_policy = if let Some(overlay_policy_id) = overlay_policy_id.as_ref() {
            let stored = self.load_overlay_policy(overlay_policy_id.as_str()).await?;
            let policy = stored.value;
            ensure_overlay_policy_supports_image(
                &policy,
                &source_kind,
                &machine_family,
                &guest_profile,
            )?;
            Some(policy)
        } else {
            None
        };

        let legal_policy = if is_apple_guest_os(&guest_os) {
            normalize_required_token("license_token", request.license_token)?;
            String::from("approved_with_license_token")
        } else {
            if request
                .license_token
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty())
            {
                return Err(PlatformError::invalid(
                    "license_token is only valid for Apple guest OS families",
                ));
            }
            String::from("approved")
        };

        if let Some((key, existing)) = self
            .find_exact_import_match(&source_kind, &source_uri, &guest_os, &architecture, &digest)
            .await?
        {
            if existing.value.legal_policy != legal_policy {
                return Err(PlatformError::conflict(
                    "existing image legal policy does not match request",
                ));
            }
            if existing.value.guest_profile_id != guest_profile_id
                || existing.value.overlay_policy_id != overlay_policy_id
            {
                return Err(PlatformError::conflict(
                    "existing image policy bindings do not match request",
                ));
            }
            let mut record = existing.value;
            let attestation_upgraded = upgrade_image_attestation_state(&mut record)?;
            let mut updated = false;
            let execution_intent =
                default_execution_intent_for_guest_profile(&record.guest_profile);
            let compatibility_requirement = build_image_compatibility_requirement(
                &record.architecture,
                &record.machine_family,
                &record.guest_profile,
                &record.preferred_boot_device,
                &record.claim_tier,
            )?;
            let compatibility_evidence = self
                .build_image_compatibility_artifacts(&record, overlay_policy.as_ref())
                .await?;
            if merge_attestation_records(&mut record.attestations, incoming_attestations.clone()) {
                updated = true;
            }
            if attestation_upgraded {
                updated = true;
            }
            if record.compatibility_requirement.as_ref() != Some(&compatibility_requirement) {
                record.compatibility_requirement = Some(compatibility_requirement);
                updated = true;
            }
            if record.execution_intent != execution_intent {
                record.execution_intent = execution_intent;
                updated = true;
            }
            if record.compatibility_evidence != compatibility_evidence {
                record.compatibility_evidence = compatibility_evidence;
                updated = true;
            }
            if updated {
                record.metadata.touch(import_fingerprint(
                    &source_kind,
                    &source_uri,
                    &guest_os,
                    &architecture,
                    &digest,
                ));
                self.images
                    .upsert(&key, record.clone(), Some(existing.version))
                    .await?;
            }
            self.append_event(
                "uvm.image.imported.v1",
                "uvm_image",
                record.id.as_str(),
                if updated {
                    "deduplicated_enriched"
                } else {
                    "deduplicated"
                },
                serde_json::json!({
                    "source_kind": record.source_kind,
                    "architecture": record.architecture,
                    "deduplicated": true,
                    "enriched_attestations": updated,
                }),
                context,
            )
            .await?;
            return json_response(StatusCode::OK, &record);
        }

        if let Some(existing) = self
            .find_content_duplicate(&guest_os, &architecture, &digest)
            .await?
        {
            return Err(PlatformError::conflict(format!(
                "image content already exists with id `{}` for the same guest_os and architecture",
                existing.id
            )));
        }

        let id = UvmImageId::generate().map_err(|error| {
            PlatformError::unavailable("failed to allocate UVM image id")
                .with_detail(error.to_string())
        })?;
        let install_media = source_kind == "iso";
        let preferred_boot_device = if install_media {
            String::from(BootDevice::Cdrom.as_str())
        } else {
            String::from(BootDevice::Disk.as_str())
        };
        let claim_tier = default_claim_tier_key();
        let execution_intent = default_execution_intent_for_guest_profile(&guest_profile);
        let compatibility_requirement = build_image_compatibility_requirement(
            &architecture,
            &machine_family,
            &guest_profile,
            &preferred_boot_device,
            &claim_tier,
        )?;
        let mut record = UvmImageRecord {
            id: id.clone(),
            source_kind,
            source_uri,
            guest_os,
            architecture,
            guest_profile,
            guest_profile_id,
            machine_family,
            install_media,
            preferred_boot_device,
            overlay_policy_id,
            digest,
            verified: false,
            attestations: incoming_attestations,
            promoted_channel: None,
            publication_manifests: Vec::new(),
            legal_policy,
            claim_tier,
            execution_intent,
            compatibility_requirement: Some(compatibility_requirement),
            compatibility_evidence: Vec::new(),
            metadata: ResourceMetadata::new(
                OwnershipScope::Platform,
                Some(id.to_string()),
                sha256_hex(id.as_str().as_bytes()),
            ),
            legacy_signature_verified: false,
            legacy_provenance_verified: false,
        };
        record.compatibility_evidence = self
            .build_image_compatibility_artifacts(&record, overlay_policy.as_ref())
            .await?;
        self.images.create(id.as_str(), record.clone()).await?;
        self.append_event(
            "uvm.image.imported.v1",
            "uvm_image",
            id.as_str(),
            "imported",
            serde_json::json!({
                "source_kind": record.source_kind,
                "architecture": record.architecture,
            }),
            context,
        )
        .await?;
        json_response(StatusCode::CREATED, &record)
    }

    async fn verify_image(
        &self,
        image_id: &str,
        request: VerifyImageRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let stored = self.load_image(image_id).await?;
        let mut record = stored.value;
        let expected_digest = normalize_digest(request.expected_digest)?;
        if let Some(expected_digest) = expected_digest.as_deref()
            && !expected_digest.eq_ignore_ascii_case(&record.digest)
        {
            return Err(PlatformError::conflict(
                "expected digest does not match stored digest",
            ));
        }
        enforce_legal_policy_for_record(&record)?;

        let require_signature = request.require_signature.unwrap_or(true);
        if require_signature
            && !image_has_attestation_kind(&record, UvmArtifactAttestationKind::Signature)
        {
            return Err(PlatformError::conflict(
                "signature evidence is required before verification",
            ));
        }

        let require_provenance = request.require_provenance.unwrap_or(true);
        if require_provenance
            && !image_has_attestation_kind(&record, UvmArtifactAttestationKind::Provenance)
        {
            return Err(PlatformError::conflict(
                "provenance evidence is required before verification",
            ));
        }

        if record.verified {
            return json_response(StatusCode::OK, &record);
        }

        record.verified = true;
        record.metadata.touch(sha256_hex(image_id.as_bytes()));
        self.images
            .upsert(image_id, record.clone(), Some(stored.version))
            .await?;
        self.append_event(
            "uvm.image.verified.v1",
            "uvm_image",
            image_id,
            "verified",
            serde_json::json!({
                "verified": record.verified,
                "attestation_kinds": image_attestation_kind_keys(&record),
            }),
            context,
        )
        .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn promote_image(
        &self,
        image_id: &str,
        request: PromoteImageRequest,
        context: &RequestContext,
    ) -> Result<http::Response<ApiBody>> {
        let stored = self.load_image(image_id).await?;
        let mut record = stored.value;
        enforce_legal_policy_for_record(&record)?;
        if !record.verified {
            return Err(PlatformError::conflict(
                "image must be verified before promotion",
            ));
        }
        if !image_has_attestation_kind(&record, UvmArtifactAttestationKind::Signature)
            || !image_has_attestation_kind(&record, UvmArtifactAttestationKind::Provenance)
        {
            return Err(PlatformError::conflict(
                "image must have signature and provenance evidence before promotion",
            ));
        }
        let overlay_policy = if let Some(overlay_policy_id) = record.overlay_policy_id.as_ref() {
            Some(
                self.load_overlay_policy(overlay_policy_id.as_str())
                    .await?
                    .value,
            )
        } else {
            None
        };
        let compatibility_evidence = self
            .build_image_compatibility_artifacts(&record, overlay_policy.as_ref())
            .await?;
        let compatibility_evidence_updated =
            if record.compatibility_evidence != compatibility_evidence {
                record.compatibility_evidence = compatibility_evidence;
                true
            } else {
                false
            };
        let host_class_explicit = request.host_class.is_some();
        let manifest = build_publication_manifest_selection(&record, request)?;
        let exact_match = self
            .resolve_exact_publication_match(&record, manifest, host_class_explicit)
            .await?;
        let legacy_backfilled = self
            .backfill_legacy_publication_manifests(image_id, &mut record, context)
            .await?;
        let existing_manifest_index = record
            .publication_manifests
            .iter()
            .position(|existing| manifest_matches(existing, &exact_match.manifest));
        if let Some(index) = existing_manifest_index
            && manifest_has_exact_match(&record.publication_manifests[index], &exact_match)
        {
            if legacy_backfilled || compatibility_evidence_updated {
                record.promoted_channel = summarize_promoted_channel(&record.publication_manifests);
                if legacy_backfilled {
                    record
                        .metadata
                        .touch(publication_manifest_fingerprint(image_id, &exact_match));
                } else {
                    record
                        .metadata
                        .touch(compatibility_evidence_state_fingerprint(
                            image_id,
                            &record.compatibility_evidence,
                        ));
                }
                self.images
                    .upsert(image_id, record.clone(), Some(stored.version))
                    .await?;
            }
            return json_response(StatusCode::OK, &record);
        }
        if let Some(overlay_policy) = overlay_policy.as_ref() {
            ensure_overlay_policy_supports_publication(overlay_policy, &exact_match.manifest)?;
        }
        let (audit_event_id, published_at) = self
            .append_event(
                "uvm.image.promoted.v1",
                "uvm_image",
                image_id,
                "promoted",
                serde_json::json!({
                    "channel": exact_match.manifest.channel.as_str(),
                    "publication_manifest_key": publication_manifest_key(image_id, &exact_match.manifest),
                    "host_class": exact_match.manifest.host_class.as_str(),
                    "machine_family": exact_match.manifest.machine_family.as_str(),
                    "guest_profile": exact_match.manifest.guest_profile.as_str(),
                    "region": exact_match.manifest.region.as_str(),
                    "cell": exact_match.manifest.cell.as_str(),
                    "compatibility_row_id": exact_match.row.id.as_str(),
                    "compatibility_match_key": exact_match.compatibility_match_key.as_str(),
                }),
                context,
            )
            .await?;
        let manifest_record =
            publication_manifest_from_exact_match(&exact_match, audit_event_id, published_at);
        if let Some(index) = existing_manifest_index {
            record.publication_manifests[index] = manifest_record;
        } else {
            record.publication_manifests.push(manifest_record);
        }
        sort_publication_manifests(&mut record.publication_manifests);
        record.promoted_channel = summarize_promoted_channel(&record.publication_manifests);
        record
            .metadata
            .touch(publication_manifest_fingerprint(image_id, &exact_match));
        self.images
            .upsert(image_id, record.clone(), Some(stored.version))
            .await?;
        json_response(StatusCode::OK, &record)
    }

    async fn backfill_legacy_publication_manifests(
        &self,
        image_id: &str,
        record: &mut UvmImageRecord,
        context: &RequestContext,
    ) -> Result<bool> {
        if !record.publication_manifests.is_empty() {
            return Ok(false);
        }
        let Some(channel) = record.promoted_channel.as_deref() else {
            return Ok(false);
        };
        let channel = normalize_channel(channel)?;
        let overlay_policy = if let Some(overlay_policy_id) = record.overlay_policy_id.as_ref() {
            Some(
                self.load_overlay_policy(overlay_policy_id.as_str())
                    .await?
                    .value,
            )
        } else {
            None
        };
        let mut exact_matches = self
            .resolve_legacy_publication_matches(record, &channel)
            .await?;
        if let Some(policy) = overlay_policy.as_ref() {
            exact_matches.retain(|exact_match| {
                ensure_overlay_policy_supports_publication(policy, &exact_match.manifest).is_ok()
            });
        }
        let fallback_manifest =
            legacy_publication_manifest_selection(record, &channel, overlay_policy.as_ref());
        let publication_manifest_keys = if exact_matches.is_empty() {
            vec![publication_manifest_key(image_id, &fallback_manifest)]
        } else {
            exact_matches
                .iter()
                .map(|exact_match| publication_manifest_key(image_id, &exact_match.manifest))
                .collect::<Vec<_>>()
        };
        let compatibility_row_ids = exact_matches
            .iter()
            .map(|exact_match| exact_match.row.id.as_str().to_owned())
            .collect::<Vec<_>>();
        let (audit_event_id, published_at) = self
            .append_event(
                "uvm.image.publication_manifests.backfilled.v1",
                "uvm_image",
                image_id,
                "publication_manifests_backfilled",
                serde_json::json!({
                    "channel": channel.as_str(),
                    "publication_manifest_keys": publication_manifest_keys,
                    "compatibility_row_ids": compatibility_row_ids,
                    "manifest_count": if exact_matches.is_empty() { 1 } else { exact_matches.len() },
                    "backfill_mode": if exact_matches.is_empty() {
                        "default_scope_fallback"
                    } else {
                        "compatibility_expansion"
                    },
                    "source": "legacy_promoted_channel",
                }),
                context,
            )
            .await?;
        if exact_matches.is_empty() {
            record
                .publication_manifests
                .push(publication_manifest_from_legacy_selection(
                    &fallback_manifest,
                    &record.claim_tier,
                    audit_event_id,
                    published_at,
                ));
        } else {
            record
                .publication_manifests
                .extend(exact_matches.iter().map(|exact_match| {
                    publication_manifest_from_exact_match(
                        exact_match,
                        audit_event_id.clone(),
                        published_at,
                    )
                }));
        }
        sort_publication_manifests(&mut record.publication_manifests);
        record.promoted_channel = summarize_promoted_channel(&record.publication_manifests);
        Ok(true)
    }

    async fn resolve_legacy_publication_matches(
        &self,
        record: &UvmImageRecord,
        channel: &str,
    ) -> Result<Vec<ExactPublicationMatch>> {
        let mut matches = self
            .compatibility
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|row| {
                row.guest_architecture == record.architecture
                    && row.machine_family == record.machine_family
                    && row.guest_profile == record.guest_profile
                    && row.claim_tier == record.claim_tier
                    && row.policy_approved
            })
            .map(|row| {
                let manifest = PublicationManifestSelection {
                    channel: channel.to_owned(),
                    host_class: row.host_class.clone(),
                    machine_family: row.machine_family.clone(),
                    guest_profile: row.guest_profile.clone(),
                    region: row.region.clone(),
                    cell: row.cell.clone(),
                };
                ExactPublicationMatch {
                    compatibility_match_key: publication_compatibility_match_key(record, &manifest),
                    manifest,
                    row,
                }
            })
            .collect::<Vec<_>>();
        matches.sort_by(|left, right| {
            compare_publication_manifest_scopes(&left.manifest, &right.manifest)
        });
        Ok(matches)
    }

    async fn resolve_exact_publication_match(
        &self,
        record: &UvmImageRecord,
        manifest: PublicationManifestSelection,
        host_class_explicit: bool,
    ) -> Result<ExactPublicationMatch> {
        let mut candidates = self
            .compatibility
            .list()
            .await?
            .into_iter()
            .filter(|(_, stored)| !stored.deleted)
            .map(|(_, stored)| stored.value)
            .filter(|row| {
                row.guest_architecture == record.architecture
                    && row.machine_family == manifest.machine_family
                    && row.guest_profile == manifest.guest_profile
                    && row.claim_tier == record.claim_tier
                    && row.region == manifest.region
                    && row.cell == manifest.cell
            })
            .collect::<Vec<_>>();
        if host_class_explicit {
            candidates.retain(|row| row.host_class == manifest.host_class);
        }
        candidates.sort_by(compare_compatibility_rows);

        if candidates.is_empty() {
            let host_class = if host_class_explicit {
                manifest.host_class.as_str()
            } else {
                "<auto>"
            };
            return Err(PlatformError::conflict(format!(
                "no exact compatibility row matches architecture `{}` machine_family `{}` guest_profile `{}` claim_tier `{}` host_class `{}` region `{}` cell `{}`",
                record.architecture,
                manifest.machine_family,
                manifest.guest_profile,
                record.claim_tier,
                host_class,
                manifest.region,
                manifest.cell,
            )));
        }
        if candidates.len() > 1 {
            let host_classes = candidates
                .iter()
                .map(|row| row.host_class.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ");
            let message = if host_class_explicit {
                format!(
                    "compatibility matrix contains multiple exact rows for host_class `{}` region `{}` cell `{}`; matching host_class set: {}",
                    manifest.host_class, manifest.region, manifest.cell, host_classes,
                )
            } else {
                format!(
                    "promotion requires explicit host_class because multiple exact compatibility rows match region `{}` cell `{}`: {}",
                    manifest.region, manifest.cell, host_classes,
                )
            };
            return Err(PlatformError::conflict(message));
        }

        let row = candidates.pop().ok_or_else(|| {
            PlatformError::conflict("failed to resolve compatibility row after candidate filtering")
        })?;
        if !row.policy_approved {
            return Err(PlatformError::conflict(format!(
                "exact compatibility row `{}` is not policy-approved",
                row.id,
            )));
        }
        let manifest = PublicationManifestSelection {
            host_class: row.host_class.clone(),
            ..manifest
        };
        Ok(ExactPublicationMatch {
            compatibility_match_key: publication_compatibility_match_key(record, &manifest),
            manifest,
            row,
        })
    }

    async fn ensure_default_compatibility(&self) -> Result<()> {
        let existing = self
            .compatibility
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .count();
        if existing > 0 {
            return Ok(());
        }

        for (
            host_family,
            arch,
            backend,
            machine_family,
            guest_profile,
            claim_tier,
            secure_boot,
            live_migration,
            approved,
            notes,
        ) in [
            (
                "linux",
                "x86_64",
                "software_dbt",
                "general_purpose_pci",
                "linux_standard",
                "compatible",
                false,
                false,
                true,
                "Portable unprivileged software backend baseline for full-VM Linux guests",
            ),
            (
                "linux",
                "aarch64",
                "software_dbt",
                "aarch64_virt",
                "linux_standard",
                "compatible",
                false,
                false,
                true,
                "Portable unprivileged software backend baseline for full-VM Arm Linux guests",
            ),
            (
                "linux",
                "x86_64",
                "kvm",
                "microvm_linux",
                "linux_standard",
                "competitive",
                true,
                true,
                true,
                "Primary accelerator path for x86 guests",
            ),
            (
                "linux",
                "aarch64",
                "kvm",
                "aarch64_virt",
                "linux_standard",
                "competitive",
                true,
                true,
                true,
                "Primary accelerator path for arm guests",
            ),
            (
                "windows",
                "x86_64",
                "hyperv_whp",
                "general_purpose_pci",
                "windows_general",
                "compatible",
                true,
                true,
                true,
                "Hyper-V/WHP path for Windows hosts",
            ),
            (
                "macos",
                "aarch64",
                "apple_virtualization",
                "aarch64_virt",
                "apple_guest",
                "research_only",
                true,
                false,
                true,
                "Apple backend with legal guardrail enforcement",
            ),
            (
                "freebsd",
                "x86_64",
                "bhyve",
                "general_purpose_pci",
                "bsd_general",
                "compatible",
                false,
                false,
                true,
                "BSD accelerator path without secure boot",
            ),
            (
                "openbsd",
                "x86_64",
                "bhyve",
                "general_purpose_pci",
                "bsd_general",
                "compatible",
                false,
                false,
                true,
                "OpenBSD bhyve-compatible policy row without secure boot",
            ),
            (
                "netbsd",
                "x86_64",
                "bhyve",
                "general_purpose_pci",
                "bsd_general",
                "compatible",
                false,
                false,
                true,
                "NetBSD bhyve-compatible policy row without secure boot",
            ),
            (
                "dragonflybsd",
                "x86_64",
                "bhyve",
                "general_purpose_pci",
                "bsd_general",
                "compatible",
                false,
                false,
                true,
                "DragonFlyBSD bhyve-compatible policy row without secure boot",
            ),
        ] {
            let id = UvmCompatibilityReportId::generate().map_err(|error| {
                PlatformError::unavailable("failed to allocate compatibility row id")
                    .with_detail(error.to_string())
            })?;
            let row = UvmCompatibilityReport {
                id: id.clone(),
                host_class: derive_compatibility_host_class_key(host_family, backend, arch),
                region: default_region_key(),
                cell: default_cell_key(),
                host_family: String::from(host_family),
                guest_architecture: String::from(arch),
                accelerator_backend: String::from(backend),
                machine_family: String::from(machine_family),
                guest_profile: String::from(guest_profile),
                secure_boot_supported: secure_boot,
                live_migration_supported: live_migration,
                policy_approved: approved,
                claim_tier: String::from(claim_tier),
                notes: String::from(notes),
            };
            let key = compatibility_variant_key(&row);
            self.compatibility.create(&key, row).await?;
        }
        Ok(())
    }

    async fn list_compatibility_revisions_for_variant(
        &self,
        variant_key: &str,
    ) -> Result<Vec<UvmCompatibilityReportRevision>> {
        let mut rows = self
            .compatibility_revisions
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted && value.value.variant_key == variant_key)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.revision
                .cmp(&right.revision)
                .then(left.active_version.cmp(&right.active_version))
        });
        Ok(rows)
    }

    async fn persist_compatibility_revision(
        &self,
        row: &UvmCompatibilityReport,
        active_version: u64,
    ) -> Result<()> {
        let variant_key = compatibility_variant_key(row);
        let existing = self
            .list_compatibility_revisions_for_variant(&variant_key)
            .await?;
        if existing
            .last()
            .is_some_and(|last| last.report == *row && last.active_version == active_version)
        {
            return Ok(());
        }
        let revision = existing.last().map_or(Ok(1_u64), |last| {
            last.revision.checked_add(1).ok_or_else(|| {
                PlatformError::conflict(format!(
                    "compatibility revision overflowed for `{variant_key}`"
                ))
            })
        })?;
        let key = compatibility_revision_key(&variant_key, revision);
        self.compatibility_revisions
            .create(
                &key,
                UvmCompatibilityReportRevision {
                    variant_key,
                    revision,
                    active_version,
                    report: row.clone(),
                },
            )
            .await?;
        Ok(())
    }

    async fn enforce_compatibility_integrity(&self) -> Result<()> {
        let mut groups: BTreeMap<String, Vec<CompatibilityRowCandidate>> = BTreeMap::new();
        for (key, stored) in self.compatibility.list().await? {
            if stored.deleted {
                continue;
            }
            let row = normalize_compatibility_row(&stored.value)?;
            let variant_key = compatibility_variant_key(&row);
            groups
                .entry(variant_key.clone())
                .or_default()
                .push(CompatibilityRowCandidate {
                    key,
                    version: stored.version,
                    updated_at: stored.updated_at,
                    variant_key,
                    row,
                });
        }

        for (variant_key, candidates) in &mut groups {
            candidates.sort_by(compare_compatibility_row_candidates);
            for candidate in candidates.iter() {
                self.persist_compatibility_revision(&candidate.row, candidate.version)
                    .await?;
            }

            let winner = candidates.last().ok_or_else(|| {
                PlatformError::conflict(format!(
                    "compatibility variant group `{variant_key}` is empty"
                ))
            })?;
            match self.compatibility.get(variant_key).await? {
                Some(stored) if !stored.deleted && stored.value == winner.row => stored.version,
                Some(stored) => {
                    let written = self
                        .compatibility
                        .upsert(variant_key, winner.row.clone(), Some(stored.version))
                        .await?;
                    self.persist_compatibility_revision(&written.value, written.version)
                        .await?;
                    written.version
                }
                None => {
                    let written = self
                        .compatibility
                        .create(variant_key, winner.row.clone())
                        .await?;
                    self.persist_compatibility_revision(&written.value, written.version)
                        .await?;
                    written.version
                }
            };

            for candidate in candidates.iter() {
                if candidate.key == candidate.variant_key {
                    continue;
                }
                let Some(current) = self.compatibility.get(&candidate.key).await? else {
                    continue;
                };
                if current.deleted || current.value != candidate.row {
                    continue;
                }
                self.compatibility
                    .soft_delete(&candidate.key, Some(current.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn upgrade_attestation_records(&self) -> Result<()> {
        let mut image_rows = self.images.list().await?;
        image_rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in image_rows {
            if stored.deleted {
                continue;
            }
            let mut record = stored.value.clone();
            if upgrade_image_attestation_state(&mut record)? {
                record
                    .metadata
                    .touch(attestation_state_fingerprint("image", key.as_str()));
                self.images
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }

        let mut firmware_rows = self.firmware_bundles.list().await?;
        firmware_rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in firmware_rows {
            if stored.deleted {
                continue;
            }
            let mut record = stored.value.clone();
            if normalize_attestation_records(&mut record.attestations)? {
                record
                    .metadata
                    .touch(attestation_state_fingerprint("firmware", key.as_str()));
                self.firmware_bundles
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }

        let mut overlay_rows = self.overlay_policies.list().await?;
        overlay_rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in overlay_rows {
            if stored.deleted {
                continue;
            }
            let mut record = stored.value.clone();
            if normalize_attestation_records(&mut record.attestations)? {
                record
                    .metadata
                    .touch(attestation_state_fingerprint("overlay", key.as_str()));
                self.overlay_policies
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }

        Ok(())
    }

    async fn enforce_firmware_policy_integrity(&self) -> Result<()> {
        let mut rows = self.firmware_bundles.list().await?;
        rows.sort_by(|left, right| left.0.cmp(&right.0));
        for (key, stored) in rows {
            if stored.deleted {
                continue;
            }
            let mut record = stored.value.clone();
            let (secure_boot_posture, signer_lineage) = normalize_firmware_policy_fields(
                &record.firmware_profile,
                record.secure_boot_capable,
                Some(record.secure_boot_posture.as_str()),
                record.signer_lineage.clone(),
            )?;
            record.secure_boot_posture = secure_boot_posture;
            record.signer_lineage = signer_lineage;
            let _ = normalize_attestation_records(&mut record.attestations)?;
            if record.policy_revision == 0 {
                record.policy_revision = default_firmware_policy_revision();
            }

            if record != stored.value {
                self.firmware_bundles
                    .upsert(&key, record, Some(stored.version))
                    .await?;
            }
        }
        Ok(())
    }

    async fn list_firmware_bundles(&self) -> Result<Vec<UvmFirmwareBundleRecord>> {
        let mut rows = self
            .firmware_bundles
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(rows)
    }

    async fn list_guest_profiles(&self) -> Result<Vec<UvmGuestProfileRecord>> {
        let mut rows = self
            .guest_profiles
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(rows)
    }

    async fn list_overlay_policies(&self) -> Result<Vec<UvmOverlayPolicyRecord>> {
        let mut rows = self
            .overlay_policies
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(rows)
    }

    async fn list_region_cell_policies(&self) -> Result<Vec<UvmRegionCellPolicyRecord>> {
        let mut rows = self
            .region_cell_policies
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(compare_region_cell_policies);
        Ok(rows)
    }

    async fn find_exact_import_match(
        &self,
        source_kind: &str,
        source_uri: &str,
        guest_os: &str,
        architecture: &str,
        digest: &str,
    ) -> Result<Option<(String, StoredDocument<UvmImageRecord>)>> {
        let records = self.images.list().await?;
        let match_row = records.into_iter().find(|(_, document)| {
            !document.deleted
                && document.value.source_kind == source_kind
                && document.value.source_uri == source_uri
                && document.value.guest_os == guest_os
                && document.value.architecture == architecture
                && document.value.digest == digest
        });
        Ok(match_row)
    }

    async fn find_content_duplicate(
        &self,
        guest_os: &str,
        architecture: &str,
        digest: &str,
    ) -> Result<Option<UvmImageRecord>> {
        let records = self.images.list().await?;
        let duplicate = records.into_iter().find_map(|(_, document)| {
            if document.deleted {
                return None;
            }
            if document.value.guest_os == guest_os
                && document.value.architecture == architecture
                && document.value.digest == digest
            {
                return Some(document.value);
            }
            None
        });
        Ok(duplicate)
    }

    async fn load_image(&self, image_id: &str) -> Result<StoredDocument<UvmImageRecord>> {
        let stored = self
            .images
            .get(image_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("image does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("image does not exist"));
        }
        Ok(stored)
    }

    async fn load_firmware_bundle(
        &self,
        firmware_id: &str,
    ) -> Result<StoredDocument<UvmFirmwareBundleRecord>> {
        let stored = self
            .firmware_bundles
            .get(firmware_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("firmware bundle does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("firmware bundle does not exist"));
        }
        Ok(stored)
    }

    async fn load_overlay_policy(
        &self,
        overlay_policy_id: &str,
    ) -> Result<StoredDocument<UvmOverlayPolicyRecord>> {
        let stored = self
            .overlay_policies
            .get(overlay_policy_id)
            .await?
            .ok_or_else(|| PlatformError::not_found("overlay policy does not exist"))?;
        if stored.deleted {
            return Err(PlatformError::not_found("overlay policy does not exist"));
        }
        Ok(stored)
    }

    async fn resolve_verified_image_artifact_path(&self, image_id: &str) -> Result<PathBuf> {
        let stored = self.load_image(image_id).await?;
        resolve_verified_local_file_uri("image", &stored.value.source_uri, stored.value.verified)
    }

    async fn resolve_verified_firmware_artifact_path(&self, firmware_id: &str) -> Result<PathBuf> {
        let stored = self.load_firmware_bundle(firmware_id).await?;
        resolve_verified_local_file_uri(
            "firmware",
            &stored.value.artifact_uri,
            stored.value.verified,
        )
    }

    async fn append_event(
        &self,
        event_type: &str,
        resource_kind: &str,
        resource_id: &str,
        action: &str,
        details: serde_json::Value,
        context: &RequestContext,
    ) -> Result<(AuditId, OffsetDateTime)> {
        let details_json = serde_json::to_string(&details).map_err(|error| {
            PlatformError::unavailable("failed to encode event details")
                .with_detail(error.to_string())
        })?;
        let event = PlatformEvent {
            header: EventHeader {
                event_id: AuditId::generate().map_err(|error| {
                    PlatformError::unavailable("failed to allocate audit id")
                        .with_detail(error.to_string())
                })?,
                event_type: event_type.to_owned(),
                schema_version: 1,
                source_service: String::from("uvm-image"),
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
                action: action.to_owned(),
                details,
            }),
        };
        let event_id = event.header.event_id.clone();
        let emitted_at = event.header.emitted_at;
        self.audit_log.append(&event).await?;
        let correlation_id = context.correlation_id.clone();
        let idempotency = sha256_hex(
            format!(
                "uvm-image-event:v1|{}|{}|{}|{}|{}|{}",
                event_type, resource_kind, resource_id, action, correlation_id, details_json
            )
            .as_bytes(),
        );
        let _ = self
            .outbox
            .enqueue(event_type, event, Some(&idempotency))
            .await?;
        Ok((event_id, emitted_at))
    }

    async fn list_images(&self) -> Result<Vec<UvmImageRecord>> {
        let mut records = self
            .images
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        records.sort_by(compare_image_records);
        Ok(records)
    }

    async fn list_compatibility_rows(&self) -> Result<Vec<UvmCompatibilityReport>> {
        let mut rows = self
            .compatibility
            .list()
            .await?
            .into_iter()
            .filter(|(_, value)| !value.deleted)
            .map(|(_, value)| value.value)
            .collect::<Vec<_>>();
        rows.sort_by(compare_compatibility_rows);
        Ok(rows)
    }

    async fn list_outbox_messages(&self) -> Result<Vec<OutboxMessage<PlatformEvent>>> {
        let mut records = self.outbox.list_all().await?;
        records.sort_by(compare_outbox_messages);
        Ok(records)
    }

    async fn image_summary(&self) -> Result<UvmImagesSummaryResponse> {
        let images = self.list_images().await?;
        let firmware_bundles = self.list_firmware_bundles().await?;
        let guest_profiles = self.list_guest_profiles().await?;
        let overlay_policies = self.list_overlay_policies().await?;
        let region_cell_policies = self.list_region_cell_policies().await?;

        let mut architecture_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut source_kind_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut signature_verified_images: usize = 0;
        let mut provenance_verified_images: usize = 0;

        for image in &images {
            *architecture_counts
                .entry(image.architecture.clone())
                .or_default() += 1;
            *source_kind_counts
                .entry(image.source_kind.clone())
                .or_default() += 1;
            if image_has_attestation_kind(image, UvmArtifactAttestationKind::Signature) {
                signature_verified_images = signature_verified_images.saturating_add(1);
            }
            if image_has_attestation_kind(image, UvmArtifactAttestationKind::Provenance) {
                provenance_verified_images = provenance_verified_images.saturating_add(1);
            }
        }

        let verified_images = images.iter().filter(|image| image.verified).count();
        let artifact_verified_images = images
            .iter()
            .filter(|image| image.verified && !image.digest.is_empty())
            .count();

        let verified_firmware_bundles = firmware_bundles
            .iter()
            .filter(|bundle| bundle.verified)
            .count();

        Ok(UvmImagesSummaryResponse {
            total_images: images.len(),
            verified_images,
            unverified_images: images.len().saturating_sub(verified_images),
            signature_verified_images,
            provenance_verified_images,
            artifact_verified_images,
            total_firmware_bundles: firmware_bundles.len(),
            verified_firmware_bundles,
            total_guest_profiles: guest_profiles.len(),
            total_overlay_policies: overlay_policies.len(),
            total_region_cell_policies: region_cell_policies.len(),
            architecture_counts,
            source_kind_counts,
        })
    }
}

impl HttpService for UvmImageService {
    fn name(&self) -> &'static str {
        "uvm-image"
    }

    fn route_claims(&self) -> &'static [uhost_runtime::RouteClaim] {
        const ROUTE_CLAIMS: &[uhost_runtime::RouteClaim] = &[
            uhost_runtime::RouteClaim::exact("/uvm/image"),
            uhost_runtime::RouteClaim::prefix("/uvm/images"),
            uhost_runtime::RouteClaim::prefix("/uvm/firmware-bundles"),
            uhost_runtime::RouteClaim::prefix("/uvm/guest-profiles"),
            uhost_runtime::RouteClaim::prefix("/uvm/overlay-policies"),
            uhost_runtime::RouteClaim::prefix("/uvm/region-cell-policies"),
            uhost_runtime::RouteClaim::prefix("/uvm/compatibility-matrix"),
            uhost_runtime::RouteClaim::prefix("/uvm/image-outbox"),
        ];
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
                (Method::GET, ["uvm", "image"]) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "service": self.name(),
                        "state_root": self.state_root,
                    }),
                )
                .map(Some),
                (Method::GET, ["uvm", "images"]) => {
                    let records = self.list_images().await?;
                    json_response(StatusCode::OK, &records).map(Some)
                }
                (Method::GET, ["uvm", "images", "summary"]) => {
                    let summary = self.image_summary().await?;
                    json_response(StatusCode::OK, &summary).map(Some)
                }
                (Method::POST, ["uvm", "images"]) => {
                    let body: ImportImageRequest = parse_json(request).await?;
                    self.import_image(body, &context).await.map(Some)
                }
                (Method::POST, ["uvm", "images", image_id, "verify"]) => {
                    let body: VerifyImageRequest = parse_json(request).await?;
                    self.verify_image(image_id, body, &context).await.map(Some)
                }
                (Method::POST, ["uvm", "images", image_id, "promote"]) => {
                    let body: PromoteImageRequest = parse_json(request).await?;
                    self.promote_image(image_id, body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "images", image_id, "artifact-path"]) => {
                    let path = self.resolve_verified_image_artifact_path(image_id).await?;
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({ "path": path.to_string_lossy() }),
                    )
                    .map(Some)
                }
                (Method::GET, ["uvm", "firmware-bundles"]) => {
                    let rows = self.list_firmware_bundles().await?;
                    json_response(StatusCode::OK, &rows).map(Some)
                }
                (Method::POST, ["uvm", "firmware-bundles"]) => {
                    let body: CreateFirmwareBundleRequest = parse_json(request).await?;
                    self.create_firmware_bundle(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "guest-profiles"]) => {
                    let rows = self.list_guest_profiles().await?;
                    json_response(StatusCode::OK, &rows).map(Some)
                }
                (Method::POST, ["uvm", "guest-profiles"]) => {
                    let body: CreateGuestProfileRequest = parse_json(request).await?;
                    self.create_guest_profile(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "overlay-policies"]) => {
                    let rows = self.list_overlay_policies().await?;
                    json_response(StatusCode::OK, &rows).map(Some)
                }
                (Method::POST, ["uvm", "overlay-policies"]) => {
                    let body: CreateOverlayPolicyRequest = parse_json(request).await?;
                    self.create_overlay_policy(body, &context).await.map(Some)
                }
                (Method::GET, ["uvm", "region-cell-policies"]) => {
                    let rows = self.list_region_cell_policies().await?;
                    json_response(StatusCode::OK, &rows).map(Some)
                }
                (Method::POST, ["uvm", "region-cell-policies"]) => {
                    let body: CreateRegionCellPolicyRequest = parse_json(request).await?;
                    self.create_region_cell_policy(body, &context)
                        .await
                        .map(Some)
                }
                (Method::GET, ["uvm", "compatibility-matrix"]) => {
                    let rows = self.list_compatibility_rows().await?;
                    json_response(StatusCode::OK, &rows).map(Some)
                }
                (Method::GET, ["uvm", "image-outbox"]) => {
                    let records = self.list_outbox_messages().await?;
                    json_response(StatusCode::OK, &records).map(Some)
                }
                (Method::GET, ["uvm", "firmware-bundles", firmware_id, "artifact-path"]) => {
                    let path = self
                        .resolve_verified_firmware_artifact_path(firmware_id)
                        .await?;
                    json_response(
                        StatusCode::OK,
                        &serde_json::json!({ "path": path.to_string_lossy() }),
                    )
                    .map(Some)
                }
                _ => Ok(None),
            }
        })
    }
}

fn normalize_source_kind(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "iso" | "raw" | "qcow2" | "vhdx" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "source_kind must be one of iso/raw/qcow2/vhdx",
        )),
    }
}

fn normalize_record_name(value: &str, field: &str) -> Result<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid(format!("{field} exceeds 128 bytes")));
    }
    if normalized.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters"
        )));
    }
    Ok(normalized.to_owned())
}

fn normalize_architecture(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "x86_64" | "aarch64" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "architecture must be `x86_64` or `aarch64`",
        )),
    }
}

fn normalize_guest_os(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid("guest_os may not be empty"));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid("guest_os exceeds 128 bytes"));
    }
    if !normalized.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.')
    }) {
        return Err(PlatformError::invalid(
            "guest_os may only contain lowercase ascii letters, digits, dots, dashes, and underscores",
        ));
    }
    Ok(normalized)
}

fn normalize_source_uri(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid("source_uri may not be empty"));
    }
    if trimmed.len() > 2048 {
        return Err(PlatformError::invalid("source_uri exceeds 2048 bytes"));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "source_uri may not contain control characters",
        ));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(PlatformError::invalid(
            "source_uri may not contain whitespace",
        ));
    }

    if let Some((scheme, rest)) = trimmed.split_once("://") {
        if scheme.is_empty() || rest.is_empty() {
            return Err(PlatformError::invalid(
                "source_uri must include a scheme and target",
            ));
        }
        if !scheme.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        }) {
            return Err(PlatformError::invalid(
                "source_uri scheme contains invalid characters",
            ));
        }
        if scheme.eq_ignore_ascii_case("file") {
            validate_local_path(rest)?;
        }
        return Ok(format!("{}://{}", scheme.to_ascii_lowercase(), rest));
    }

    if is_windows_absolute_path(trimmed) || trimmed.starts_with('/') {
        validate_local_path(trimmed)?;
        return Ok(trimmed.to_owned());
    }

    Err(PlatformError::invalid(
        "source_uri must be an absolute path or include a URI scheme",
    ))
}

fn resolve_verified_local_file_uri(kind: &str, uri: &str, verified: bool) -> Result<PathBuf> {
    if !verified {
        return Err(PlatformError::conflict(format!(
            "{kind} artifact must be verified before the local path can be resolved"
        )));
    }
    parse_file_uri_to_path(kind, uri)
}

fn parse_file_uri_to_path(kind: &str, uri: &str) -> Result<PathBuf> {
    let remainder = uri.strip_prefix("file://").ok_or_else(|| {
        PlatformError::invalid(format!(
            "{kind} artifact URI must use the file:// scheme to expose a local path"
        ))
    })?;
    if remainder.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{kind} file URI is missing a path"
        )));
    }
    let path_str = if remainder.starts_with('/') {
        remainder.to_owned()
    } else if let Some((host, rest)) = remainder.split_once('/') {
        if host.is_empty() || host.eq_ignore_ascii_case("localhost") {
            format!("/{rest}")
        } else {
            return Err(PlatformError::invalid(format!(
                "{kind} file URI host `{host}` may only be empty or localhost"
            )));
        }
    } else {
        return Err(PlatformError::invalid(format!(
            "{kind} file URI must include a path after the scheme"
        )));
    };
    let path = PathBuf::from(path_str);
    if !path.is_absolute() {
        return Err(PlatformError::invalid(format!(
            "{kind} file URI resolves to a non-absolute path"
        )));
    }
    Ok(path)
}

fn normalize_digest(value: Option<String>) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            let digest = normalized
                .strip_prefix("sha256:")
                .unwrap_or(normalized.as_str());
            if digest.is_empty() {
                return Err(PlatformError::invalid("digest may not be empty"));
            }
            if digest.len() != 64
                || !digest
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
            {
                return Err(PlatformError::invalid(
                    "digest must be a 64-character hex string",
                ));
            }
            Ok(Some(digest.to_owned()))
        }
    }
}

fn build_attestation_records(
    signature_attestation: Option<String>,
    provenance_attestation: Option<String>,
) -> Result<Vec<UvmArtifactAttestationRecord>> {
    let recorded_at = OffsetDateTime::now_utc();
    let mut attestations = Vec::new();
    if let Some(reference) =
        normalize_attestation_reference("signature_attestation", signature_attestation)?
    {
        attestations.push(UvmArtifactAttestationRecord {
            kind: UvmArtifactAttestationKind::Signature,
            reference,
            recorded_at,
        });
    }
    if let Some(reference) =
        normalize_attestation_reference("provenance_attestation", provenance_attestation)?
    {
        attestations.push(UvmArtifactAttestationRecord {
            kind: UvmArtifactAttestationKind::Provenance,
            reference,
            recorded_at,
        });
    }
    sort_attestation_records(&mut attestations);
    Ok(attestations)
}

fn normalize_attestation_reference(
    field: &'static str,
    value: Option<String>,
) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(PlatformError::invalid(format!("{field} may not be empty")));
            }
            if trimmed.len() > 4096 {
                return Err(PlatformError::invalid(format!(
                    "{field} exceeds 4096 bytes"
                )));
            }
            if trimmed.chars().any(|character| character.is_control()) {
                return Err(PlatformError::invalid(format!(
                    "{field} may not contain control characters"
                )));
            }
            if trimmed.chars().any(char::is_whitespace) {
                return Err(PlatformError::invalid(format!(
                    "{field} may not contain whitespace"
                )));
            }
            Ok(Some(trimmed.to_owned()))
        }
    }
}

fn normalize_attestation_records(
    attestations: &mut Vec<UvmArtifactAttestationRecord>,
) -> Result<bool> {
    let mut normalized: Vec<UvmArtifactAttestationRecord> = Vec::with_capacity(attestations.len());
    for record in std::mem::take(attestations) {
        let Some(reference) =
            normalize_attestation_reference("attestation.reference", Some(record.reference))?
        else {
            continue;
        };
        if let Some(existing) = normalized
            .iter_mut()
            .find(|existing| existing.kind == record.kind && existing.reference == reference)
        {
            if record.recorded_at < existing.recorded_at {
                existing.recorded_at = record.recorded_at;
            }
            continue;
        }
        normalized.push(UvmArtifactAttestationRecord {
            kind: record.kind,
            reference,
            recorded_at: record.recorded_at,
        });
    }
    sort_attestation_records(&mut normalized);
    let changed = *attestations != normalized;
    *attestations = normalized;
    Ok(changed)
}

fn sort_attestation_records(attestations: &mut [UvmArtifactAttestationRecord]) {
    attestations.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.reference.cmp(&right.reference))
            .then_with(|| left.recorded_at.cmp(&right.recorded_at))
    });
}

fn merge_attestation_records(
    existing: &mut Vec<UvmArtifactAttestationRecord>,
    incoming: Vec<UvmArtifactAttestationRecord>,
) -> bool {
    let mut changed = false;
    for record in incoming {
        if existing.iter().any(|existing_record| {
            existing_record.kind == record.kind && existing_record.reference == record.reference
        }) {
            continue;
        }
        existing.push(record);
        changed = true;
    }
    if changed {
        sort_attestation_records(existing);
    }
    changed
}

fn artifact_has_attestation_kind(
    attestations: &[UvmArtifactAttestationRecord],
    kind: UvmArtifactAttestationKind,
) -> bool {
    attestations.iter().any(|record| record.kind == kind)
}

fn attestation_kind_keys(attestations: &[UvmArtifactAttestationRecord]) -> Vec<String> {
    let mut kinds = attestations
        .iter()
        .map(|record| String::from(record.kind.as_str()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    kinds.sort();
    kinds
}

fn legacy_image_attestation(
    kind: UvmArtifactAttestationKind,
    recorded_at: OffsetDateTime,
) -> UvmArtifactAttestationRecord {
    UvmArtifactAttestationRecord {
        kind,
        reference: format!("legacy://{}", kind.as_str()),
        recorded_at,
    }
}

fn upgrade_image_attestation_state(record: &mut UvmImageRecord) -> Result<bool> {
    let mut changed = normalize_attestation_records(&mut record.attestations)?;
    if record.legacy_signature_verified {
        record.legacy_signature_verified = false;
        merge_attestation_records(
            &mut record.attestations,
            vec![legacy_image_attestation(
                UvmArtifactAttestationKind::Signature,
                record.metadata.updated_at,
            )],
        );
        changed = true;
    }
    if record.legacy_provenance_verified {
        record.legacy_provenance_verified = false;
        merge_attestation_records(
            &mut record.attestations,
            vec![legacy_image_attestation(
                UvmArtifactAttestationKind::Provenance,
                record.metadata.updated_at,
            )],
        );
        changed = true;
    }
    Ok(changed)
}

fn image_has_attestation_kind(record: &UvmImageRecord, kind: UvmArtifactAttestationKind) -> bool {
    artifact_has_attestation_kind(&record.attestations, kind)
        || match kind {
            UvmArtifactAttestationKind::Signature => record.legacy_signature_verified,
            UvmArtifactAttestationKind::Provenance => record.legacy_provenance_verified,
        }
}

fn image_attestation_kind_keys(record: &UvmImageRecord) -> Vec<String> {
    let mut kinds = attestation_kind_keys(&record.attestations)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    if record.legacy_signature_verified {
        let _ = kinds.insert(String::from(UvmArtifactAttestationKind::Signature.as_str()));
    }
    if record.legacy_provenance_verified {
        let _ = kinds.insert(String::from(
            UvmArtifactAttestationKind::Provenance.as_str(),
        ));
    }
    kinds.into_iter().collect()
}

fn attestation_state_fingerprint(resource_kind: &str, resource_id: &str) -> String {
    sha256_hex(format!("uvm-{resource_kind}-attestations:v1|{resource_id}").as_bytes())
}

fn normalize_required_token(field: &'static str, value: Option<String>) -> Result<String> {
    let token = value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| PlatformError::invalid(format!("{field} may not be empty")))?;
    if token.len() < 16 {
        return Err(PlatformError::invalid(format!(
            "{field} must be at least 16 characters"
        )));
    }
    if token.len() > 1024 {
        return Err(PlatformError::invalid(format!(
            "{field} exceeds 1024 bytes"
        )));
    }
    if token.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain control characters"
        )));
    }
    if token.chars().any(char::is_whitespace) {
        return Err(PlatformError::invalid(format!(
            "{field} may not contain whitespace"
        )));
    }
    Ok(token.to_owned())
}

fn normalize_host_family(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "linux" | "windows" | "macos" | "freebsd" | "openbsd" | "netbsd" | "dragonflybsd"
        | "illumos" | "other" => Ok(normalized),
        _ => Err(PlatformError::invalid("unsupported host_family value")),
    }
}

fn normalize_backend_key(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "software_dbt" | "kvm" | "hyperv_whp" | "apple_virtualization" | "bhyve" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "unsupported accelerator_backend value",
        )),
    }
}

fn default_machine_family_key() -> String {
    String::from(MachineFamily::GeneralPurposePci.as_str())
}

fn default_guest_profile_key() -> String {
    String::from(GuestProfile::LinuxStandard.as_str())
}

fn default_host_class_key() -> String {
    String::from("default")
}

fn default_region_key() -> String {
    String::from("global")
}

fn default_cell_key() -> String {
    String::from("global")
}

fn derive_compatibility_host_class_key(
    host_family: &str,
    accelerator_backend: &str,
    guest_architecture: &str,
) -> String {
    format!("{host_family}-{accelerator_backend}-{guest_architecture}")
}

fn default_claim_tier_key() -> String {
    String::from(ClaimTier::Compatible.as_str())
}

fn default_boot_device_key() -> String {
    String::from(BootDevice::Disk.as_str())
}

fn default_overlay_chain_base_source_kinds() -> Vec<String> {
    ["iso", "qcow2", "raw", "vhdx"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn default_overlay_chain_machine_families() -> Vec<String> {
    [
        MachineFamily::Aarch64Virt.as_str(),
        MachineFamily::GeneralPurposePci.as_str(),
        MachineFamily::MicrovmLinux.as_str(),
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn default_overlay_chain_guest_profiles() -> Vec<String> {
    [
        GuestProfile::AppleGuest.as_str(),
        GuestProfile::BsdGeneral.as_str(),
        GuestProfile::LinuxDirectKernel.as_str(),
        GuestProfile::LinuxStandard.as_str(),
        GuestProfile::WindowsGeneral.as_str(),
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn default_overlay_publication_channels() -> Vec<String> {
    ["canary", "preview", "stable"]
        .into_iter()
        .map(String::from)
        .collect()
}

const fn default_firmware_policy_revision() -> u32 {
    1
}

fn default_execution_intent_for_guest_profile(guest_profile: &str) -> UvmExecutionIntent {
    GuestProfile::parse(guest_profile)
        .map(UvmExecutionIntent::default_for_guest_profile)
        .unwrap_or_default()
}

fn guest_architecture_from_key(value: &str) -> GuestArchitecture {
    match value {
        "aarch64" => GuestArchitecture::Aarch64,
        _ => GuestArchitecture::X86_64,
    }
}

fn default_guest_profile_for_guest_os(guest_os: &str) -> String {
    String::from(GuestProfile::default_for_guest(guest_os).as_str())
}

fn default_machine_family_for_guest(architecture: &str, guest_os: &str) -> String {
    String::from(
        MachineFamily::default_for_guest(guest_architecture_from_key(architecture), guest_os)
            .as_str(),
    )
}

fn normalize_firmware_profile(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "uefi_secure" | "uefi_standard" | "bios" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "firmware_profile must be `uefi_secure`, `uefi_standard`, or `bios`",
        )),
    }
}

fn normalize_firmware_secure_boot_posture(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "required" | "optional" | "unsupported" | "audit_pending" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "secure_boot_posture must be `required`, `optional`, `unsupported`, or `audit_pending`",
        )),
    }
}

fn normalize_firmware_signer_role(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "platform_root" | "platform_key" | "key_exchange_key" | "signature_database"
        | "bundle_signer" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "signer role must be `platform_root`, `platform_key`, `key_exchange_key`, `signature_database`, or `bundle_signer`",
        )),
    }
}

fn normalize_firmware_signer_lineage(
    signer_lineage: Vec<UvmFirmwareSignerLineageEntry>,
) -> Result<Vec<UvmFirmwareSignerLineageEntry>> {
    if signer_lineage.len() > 8 {
        return Err(PlatformError::invalid(
            "signer_lineage may not contain more than 8 entries",
        ));
    }
    let mut seen_roles = BTreeSet::new();
    signer_lineage
        .into_iter()
        .map(|entry| {
            let role = normalize_firmware_signer_role(&entry.role)?;
            if !seen_roles.insert(role.clone()) {
                return Err(PlatformError::invalid(
                    "signer_lineage roles must be unique within one firmware policy",
                ));
            }
            let signer = normalize_record_name(&entry.signer, "signer_lineage signer")?;
            let issuer = entry
                .issuer
                .as_deref()
                .map(|value| normalize_record_name(value, "signer_lineage issuer"))
                .transpose()?;
            Ok(UvmFirmwareSignerLineageEntry {
                role,
                signer,
                issuer,
            })
        })
        .collect()
}

fn derive_firmware_secure_boot_posture(
    firmware_profile: &str,
    secure_boot_capable: bool,
    signer_lineage: &[UvmFirmwareSignerLineageEntry],
) -> String {
    if firmware_profile == "bios" || !secure_boot_capable {
        return String::from("unsupported");
    }
    if signer_lineage.is_empty() {
        return String::from("audit_pending");
    }
    if firmware_profile == "uefi_secure" {
        String::from("required")
    } else {
        String::from("optional")
    }
}

fn validate_firmware_policy_fields(
    firmware_profile: &str,
    secure_boot_capable: bool,
    secure_boot_posture: &str,
    signer_lineage: &[UvmFirmwareSignerLineageEntry],
) -> Result<()> {
    if firmware_profile == "bios" && secure_boot_capable {
        return Err(PlatformError::invalid(
            "bios firmware bundles may not claim secure_boot_capable",
        ));
    }
    if firmware_profile == "uefi_secure" && !secure_boot_capable {
        return Err(PlatformError::invalid(
            "firmware_profile `uefi_secure` requires secure_boot_capable=true",
        ));
    }

    match secure_boot_posture {
        "required" => {
            if firmware_profile != "uefi_secure" {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `required` requires firmware_profile `uefi_secure`",
                ));
            }
            if !secure_boot_capable {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `required` requires secure_boot_capable=true",
                ));
            }
            if signer_lineage.is_empty() {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `required` requires signer_lineage",
                ));
            }
        }
        "optional" => {
            if firmware_profile == "uefi_secure" {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `optional` is not valid for firmware_profile `uefi_secure`",
                ));
            }
            if firmware_profile == "bios" {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `optional` is not valid for bios firmware",
                ));
            }
            if !secure_boot_capable {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `optional` requires secure_boot_capable=true",
                ));
            }
            if signer_lineage.is_empty() {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `optional` requires signer_lineage",
                ));
            }
        }
        "unsupported" => {
            if secure_boot_capable {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `unsupported` requires secure_boot_capable=false",
                ));
            }
            if !signer_lineage.is_empty() {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `unsupported` may not include signer_lineage",
                ));
            }
        }
        "audit_pending" => {
            if firmware_profile == "bios" {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `audit_pending` is not valid for bios firmware",
                ));
            }
            if !secure_boot_capable {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `audit_pending` requires secure_boot_capable=true",
                ));
            }
            if !signer_lineage.is_empty() {
                return Err(PlatformError::invalid(
                    "secure_boot_posture `audit_pending` requires an empty signer_lineage",
                ));
            }
        }
        _ => {
            return Err(PlatformError::invalid(
                "unsupported secure_boot_posture value",
            ));
        }
    }

    Ok(())
}

fn normalize_firmware_policy_fields(
    firmware_profile: &str,
    secure_boot_capable: bool,
    secure_boot_posture: Option<&str>,
    signer_lineage: Vec<UvmFirmwareSignerLineageEntry>,
) -> Result<(String, Vec<UvmFirmwareSignerLineageEntry>)> {
    let signer_lineage = normalize_firmware_signer_lineage(signer_lineage)?;
    let secure_boot_posture = match secure_boot_posture
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => normalize_firmware_secure_boot_posture(value)?,
        None => derive_firmware_secure_boot_posture(
            firmware_profile,
            secure_boot_capable,
            &signer_lineage,
        ),
    };
    validate_firmware_policy_fields(
        firmware_profile,
        secure_boot_capable,
        &secure_boot_posture,
        &signer_lineage,
    )?;
    Ok((secure_boot_posture, signer_lineage))
}

fn normalize_boot_path(value: &str) -> Result<String> {
    BootPath::parse(value).map(|value| String::from(value.as_str()))
}

fn normalize_root_mode(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "read_only_base" | "writable_cow" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "root_mode must be one of read_only_base/writable_cow",
        )),
    }
}

fn normalize_rule_keys<F>(values: Vec<String>, field: &str, normalizer: F) -> Result<Vec<String>>
where
    F: Fn(&str) -> Result<String>,
{
    if values.is_empty() {
        return Err(PlatformError::invalid(format!(
            "{field} may not be empty when provided"
        )));
    }
    let mut normalized = std::collections::BTreeSet::new();
    for value in values {
        normalized.insert(normalizer(&value)?);
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_optional_rule_keys<F>(
    values: Vec<String>,
    field: &str,
    normalizer: F,
) -> Result<Vec<String>>
where
    F: Fn(&str) -> Result<String>,
{
    if values.is_empty() {
        return Ok(Vec::new());
    }
    normalize_rule_keys(values, field, normalizer)
}

fn normalize_overlay_chain_compatibility(
    value: Option<UvmOverlayChainCompatibilityRules>,
) -> Result<UvmOverlayChainCompatibilityRules> {
    let Some(value) = value else {
        return Ok(UvmOverlayChainCompatibilityRules::default());
    };
    Ok(UvmOverlayChainCompatibilityRules {
        base_source_kinds: normalize_rule_keys(
            value.base_source_kinds,
            "chain_compatibility.base_source_kinds",
            normalize_source_kind,
        )?,
        machine_families: normalize_rule_keys(
            value.machine_families,
            "chain_compatibility.machine_families",
            normalize_machine_family,
        )?,
        guest_profiles: normalize_rule_keys(
            value.guest_profiles,
            "chain_compatibility.guest_profiles",
            normalize_guest_profile,
        )?,
    })
}

fn normalize_overlay_publication_rules(
    value: Option<UvmOverlayPublicationRules>,
) -> Result<UvmOverlayPublicationRules> {
    let Some(value) = value else {
        return Ok(UvmOverlayPublicationRules::default());
    };
    Ok(UvmOverlayPublicationRules {
        allowed_channels: normalize_rule_keys(
            value.allowed_channels,
            "publication.allowed_channels",
            normalize_channel,
        )?,
        allowed_host_classes: normalize_optional_rule_keys(
            value.allowed_host_classes,
            "publication.allowed_host_classes",
            normalize_host_class,
        )?,
        allowed_regions: normalize_optional_rule_keys(
            value.allowed_regions,
            "publication.allowed_regions",
            |entry| normalize_publication_scope(entry, "publication.allowed_regions"),
        )?,
        allowed_cells: normalize_optional_rule_keys(
            value.allowed_cells,
            "publication.allowed_cells",
            |entry| normalize_publication_scope(entry, "publication.allowed_cells"),
        )?,
    })
}

fn is_linux_guest_os(guest_os: &str) -> bool {
    guest_os.contains("linux")
        || guest_os.starts_with("ubuntu")
        || guest_os.starts_with("debian")
        || guest_os.starts_with("alpine")
        || guest_os.starts_with("fedora")
        || guest_os.starts_with("centos")
        || guest_os.starts_with("rhel")
        || guest_os.starts_with("arch")
        || guest_os.starts_with("sles")
        || guest_os.starts_with("opensuse")
}

fn is_windows_guest_os(guest_os: &str) -> bool {
    guest_os.contains("windows")
}

fn is_bsd_guest_os(guest_os: &str) -> bool {
    guest_os.contains("freebsd")
        || guest_os.contains("openbsd")
        || guest_os.contains("netbsd")
        || guest_os.contains("dragonflybsd")
        || guest_os.contains("bsd")
}

fn guest_profile_supports_guest_os(profile: &str, guest_os: &str) -> bool {
    match GuestProfile::parse(profile) {
        Ok(GuestProfile::LinuxDirectKernel | GuestProfile::LinuxStandard) => {
            is_linux_guest_os(guest_os)
        }
        Ok(GuestProfile::WindowsGeneral) => is_windows_guest_os(guest_os),
        Ok(GuestProfile::BsdGeneral) => is_bsd_guest_os(guest_os),
        Ok(GuestProfile::AppleGuest) => is_apple_guest_os(guest_os),
        Err(_) => false,
    }
}

fn normalize_machine_family(value: &str) -> Result<String> {
    MachineFamily::parse(value).map(|value| String::from(value.as_str()))
}

fn normalize_guest_profile(value: &str) -> Result<String> {
    GuestProfile::parse(value).map(|value| String::from(value.as_str()))
}

fn normalize_claim_tier(value: &str) -> Result<String> {
    ClaimTier::parse(value).map(|value| String::from(value.as_str()))
}

fn normalize_notes(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "compatibility notes may not be empty",
        ));
    }
    if trimmed.len() > 512 {
        return Err(PlatformError::invalid(
            "compatibility notes exceed 512 bytes",
        ));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "compatibility notes may not contain control characters",
        ));
    }
    Ok(trimmed.to_owned())
}

fn validate_local_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(PlatformError::invalid("local path target may not be empty"));
    }
    if path.split(['/', '\\']).any(|segment| segment == "..") {
        return Err(PlatformError::invalid(
            "local path target may not contain parent traversal segments",
        ));
    }
    Ok(())
}

fn is_windows_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 3 {
        return false;
    }
    bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/')
}

fn enforce_legal_policy_for_record(record: &UvmImageRecord) -> Result<()> {
    if is_apple_guest_os(&record.guest_os) {
        if record.architecture != "aarch64" {
            return Err(PlatformError::conflict(
                "apple guest images require aarch64 architecture",
            ));
        }
        if record.legal_policy != "approved_with_license_token" {
            return Err(PlatformError::conflict(
                "apple guest images require license-token legal approval",
            ));
        }
        return Ok(());
    }

    if record.legal_policy != "approved" {
        return Err(PlatformError::conflict(
            "non-apple images must use `approved` legal policy",
        ));
    }
    Ok(())
}

fn enforce_guest_image_guardrails(guest_os: &str, architecture: &str) -> Result<()> {
    if is_apple_guest_os(guest_os) && architecture != "aarch64" {
        return Err(PlatformError::invalid(
            "apple guest images require aarch64 architecture",
        ));
    }
    Ok(())
}

fn import_fingerprint(
    source_kind: &str,
    source_uri: &str,
    guest_os: &str,
    architecture: &str,
    digest: &str,
) -> String {
    sha256_hex(
        format!(
            "uvm-image-import:v1|{source_kind}|{source_uri}|{guest_os}|{architecture}|{digest}"
        )
        .as_bytes(),
    )
}

fn compare_image_records(left: &UvmImageRecord, right: &UvmImageRecord) -> std::cmp::Ordering {
    left.source_kind
        .cmp(&right.source_kind)
        .then(left.guest_os.cmp(&right.guest_os))
        .then(left.architecture.cmp(&right.architecture))
        .then(left.source_uri.cmp(&right.source_uri))
        .then(left.digest.cmp(&right.digest))
        .then(left.id.as_str().cmp(right.id.as_str()))
}

fn compare_compatibility_rows(
    left: &UvmCompatibilityReport,
    right: &UvmCompatibilityReport,
) -> std::cmp::Ordering {
    left.host_family
        .cmp(&right.host_family)
        .then(left.guest_architecture.cmp(&right.guest_architecture))
        .then(left.accelerator_backend.cmp(&right.accelerator_backend))
        .then(left.machine_family.cmp(&right.machine_family))
        .then(left.guest_profile.cmp(&right.guest_profile))
        .then(left.claim_tier.cmp(&right.claim_tier))
        .then(left.host_class.cmp(&right.host_class))
        .then(left.region.cmp(&right.region))
        .then(left.cell.cmp(&right.cell))
        .then(left.notes.cmp(&right.notes))
        .then(left.id.as_str().cmp(right.id.as_str()))
}

fn compare_compatibility_row_candidates(
    left: &CompatibilityRowCandidate,
    right: &CompatibilityRowCandidate,
) -> std::cmp::Ordering {
    left.updated_at
        .cmp(&right.updated_at)
        .then(left.version.cmp(&right.version))
        .then(left.key.cmp(&right.key))
}

fn compare_outbox_messages(
    left: &OutboxMessage<PlatformEvent>,
    right: &OutboxMessage<PlatformEvent>,
) -> std::cmp::Ordering {
    left.created_at
        .cmp(&right.created_at)
        .then(left.topic.cmp(&right.topic))
        .then(left.id.cmp(&right.id))
}

fn compare_region_cell_policies(
    left: &UvmRegionCellPolicyRecord,
    right: &UvmRegionCellPolicyRecord,
) -> std::cmp::Ordering {
    left.region
        .cmp(&right.region)
        .then(left.cell.cmp(&right.cell))
        .then(left.policy_mode.cmp(&right.policy_mode))
        .then(left.name.cmp(&right.name))
        .then(left.id.as_str().cmp(right.id.as_str()))
}

fn compare_publication_manifest_scopes(
    left: &PublicationManifestSelection,
    right: &PublicationManifestSelection,
) -> std::cmp::Ordering {
    left.channel
        .cmp(&right.channel)
        .then(left.host_class.cmp(&right.host_class))
        .then(left.machine_family.cmp(&right.machine_family))
        .then(left.guest_profile.cmp(&right.guest_profile))
        .then(left.region.cmp(&right.region))
        .then(left.cell.cmp(&right.cell))
}

fn compare_publication_manifests(
    left: &UvmImagePublicationManifest,
    right: &UvmImagePublicationManifest,
) -> std::cmp::Ordering {
    compare_publication_manifest_scopes(
        &PublicationManifestSelection {
            channel: left.channel.clone(),
            host_class: left.host_class.clone(),
            machine_family: left.machine_family.clone(),
            guest_profile: left.guest_profile.clone(),
            region: left.region.clone(),
            cell: left.cell.clone(),
        },
        &PublicationManifestSelection {
            channel: right.channel.clone(),
            host_class: right.host_class.clone(),
            machine_family: right.machine_family.clone(),
            guest_profile: right.guest_profile.clone(),
            region: right.region.clone(),
            cell: right.cell.clone(),
        },
    )
    .then(
        left.compatibility_match_key
            .cmp(&right.compatibility_match_key),
    )
    .then(left.published_at.cmp(&right.published_at))
    .then(
        left.audit_event_id
            .as_str()
            .cmp(right.audit_event_id.as_str()),
    )
}

fn same_publication_manifest_scope(
    left: &UvmImagePublicationManifest,
    right: &UvmImagePublicationManifest,
) -> bool {
    left.channel == right.channel
        && left.host_class == right.host_class
        && left.machine_family == right.machine_family
        && left.guest_profile == right.guest_profile
        && left.region == right.region
        && left.cell == right.cell
}

fn compare_publication_manifest_authority(
    left: &UvmImagePublicationManifest,
    right: &UvmImagePublicationManifest,
) -> std::cmp::Ordering {
    left.compatibility_row_id
        .is_some()
        .cmp(&right.compatibility_row_id.is_some())
        .then(
            (!left.compatibility_match_key.is_empty())
                .cmp(&!right.compatibility_match_key.is_empty()),
        )
        .then(left.published_at.cmp(&right.published_at))
        .then(
            left.compatibility_row_id
                .as_ref()
                .map(|id| id.as_str())
                .cmp(&right.compatibility_row_id.as_ref().map(|id| id.as_str())),
        )
        .then(
            left.compatibility_match_key
                .cmp(&right.compatibility_match_key),
        )
        .then(left.host_family.cmp(&right.host_family))
        .then(left.accelerator_backend.cmp(&right.accelerator_backend))
        .then(left.claim_tier.cmp(&right.claim_tier))
        .then(left.secure_boot_supported.cmp(&right.secure_boot_supported))
        .then(
            left.live_migration_supported
                .cmp(&right.live_migration_supported),
        )
        .then(left.policy_approved.cmp(&right.policy_approved))
        .then(left.compatibility_notes.cmp(&right.compatibility_notes))
        .then(
            left.audit_event_id
                .as_str()
                .cmp(right.audit_event_id.as_str()),
        )
}

fn sort_publication_manifests(manifests: &mut Vec<UvmImagePublicationManifest>) {
    manifests.sort_by(compare_publication_manifests);
    let mut deduped = Vec::with_capacity(manifests.len());
    for manifest in manifests.drain(..) {
        if let Some(existing) = deduped.last_mut()
            && same_publication_manifest_scope(existing, &manifest)
        {
            if compare_publication_manifest_authority(&manifest, existing)
                == std::cmp::Ordering::Greater
            {
                *existing = manifest;
            }
            continue;
        }
        deduped.push(manifest);
    }
    *manifests = deduped;
}

fn build_publication_manifest_selection(
    record: &UvmImageRecord,
    request: PromoteImageRequest,
) -> Result<PublicationManifestSelection> {
    let channel = normalize_channel(&request.channel)?;
    let host_class = request
        .host_class
        .map(|value| normalize_host_class(&value))
        .transpose()?
        .unwrap_or_else(default_host_class_key);
    let machine_family = request
        .machine_family
        .map(|value| normalize_machine_family(&value))
        .transpose()?
        .unwrap_or_else(|| record.machine_family.clone());
    if machine_family != record.machine_family {
        return Err(PlatformError::conflict(
            "promotion manifest machine_family must match the image contract until variant matrix revisions land",
        ));
    }
    let guest_profile = request
        .guest_profile
        .map(|value| normalize_guest_profile(&value))
        .transpose()?
        .unwrap_or_else(|| record.guest_profile.clone());
    if guest_profile != record.guest_profile {
        return Err(PlatformError::conflict(
            "promotion manifest guest_profile must match the image contract until variant matrix revisions land",
        ));
    }
    let region = request
        .region
        .map(|value| normalize_publication_scope(&value, "region"))
        .transpose()?
        .unwrap_or_else(default_region_key);
    let cell = request
        .cell
        .map(|value| normalize_publication_scope(&value, "cell"))
        .transpose()?
        .unwrap_or_else(default_cell_key);
    Ok(PublicationManifestSelection {
        channel,
        host_class,
        machine_family,
        guest_profile,
        region,
        cell,
    })
}

fn manifest_matches(
    existing: &UvmImagePublicationManifest,
    manifest: &PublicationManifestSelection,
) -> bool {
    existing.channel == manifest.channel
        && existing.host_class == manifest.host_class
        && existing.machine_family == manifest.machine_family
        && existing.guest_profile == manifest.guest_profile
        && existing.region == manifest.region
        && existing.cell == manifest.cell
}

fn manifest_has_exact_match(
    existing: &UvmImagePublicationManifest,
    exact_match: &ExactPublicationMatch,
) -> bool {
    manifest_matches(existing, &exact_match.manifest)
        && existing.compatibility_row_id.as_ref() == Some(&exact_match.row.id)
        && existing.compatibility_match_key == exact_match.compatibility_match_key
        && existing.host_family == exact_match.row.host_family
        && existing.accelerator_backend == exact_match.row.accelerator_backend
        && existing.claim_tier == exact_match.row.claim_tier
        && existing.secure_boot_supported == exact_match.row.secure_boot_supported
        && existing.live_migration_supported == exact_match.row.live_migration_supported
        && existing.policy_approved == exact_match.row.policy_approved
        && existing.compatibility_notes == exact_match.row.notes
}

fn legacy_publication_manifest_selection(
    record: &UvmImageRecord,
    channel: &str,
    overlay_policy: Option<&UvmOverlayPolicyRecord>,
) -> PublicationManifestSelection {
    let host_class = overlay_policy
        .and_then(|policy| policy.publication.allowed_host_classes.first().cloned())
        .unwrap_or_else(default_host_class_key);
    let region = overlay_policy
        .and_then(|policy| policy.publication.allowed_regions.first().cloned())
        .unwrap_or_else(default_region_key);
    let cell = overlay_policy
        .and_then(|policy| policy.publication.allowed_cells.first().cloned())
        .unwrap_or_else(default_cell_key);
    PublicationManifestSelection {
        channel: channel.to_owned(),
        host_class,
        machine_family: record.machine_family.clone(),
        guest_profile: record.guest_profile.clone(),
        region,
        cell,
    }
}

fn publication_manifest_from_exact_match(
    exact_match: &ExactPublicationMatch,
    audit_event_id: AuditId,
    published_at: OffsetDateTime,
) -> UvmImagePublicationManifest {
    UvmImagePublicationManifest {
        channel: exact_match.manifest.channel.clone(),
        host_class: exact_match.manifest.host_class.clone(),
        machine_family: exact_match.manifest.machine_family.clone(),
        guest_profile: exact_match.manifest.guest_profile.clone(),
        region: exact_match.manifest.region.clone(),
        cell: exact_match.manifest.cell.clone(),
        compatibility_row_id: Some(exact_match.row.id.clone()),
        compatibility_match_key: exact_match.compatibility_match_key.clone(),
        host_family: exact_match.row.host_family.clone(),
        accelerator_backend: exact_match.row.accelerator_backend.clone(),
        claim_tier: exact_match.row.claim_tier.clone(),
        secure_boot_supported: exact_match.row.secure_boot_supported,
        live_migration_supported: exact_match.row.live_migration_supported,
        policy_approved: exact_match.row.policy_approved,
        compatibility_notes: exact_match.row.notes.clone(),
        audit_event_id,
        published_at,
    }
}

fn publication_manifest_from_legacy_selection(
    manifest: &PublicationManifestSelection,
    claim_tier: &str,
    audit_event_id: AuditId,
    published_at: OffsetDateTime,
) -> UvmImagePublicationManifest {
    UvmImagePublicationManifest {
        channel: manifest.channel.clone(),
        host_class: manifest.host_class.clone(),
        machine_family: manifest.machine_family.clone(),
        guest_profile: manifest.guest_profile.clone(),
        region: manifest.region.clone(),
        cell: manifest.cell.clone(),
        compatibility_row_id: None,
        compatibility_match_key: String::new(),
        host_family: String::new(),
        accelerator_backend: String::new(),
        claim_tier: claim_tier.to_owned(),
        secure_boot_supported: false,
        live_migration_supported: false,
        policy_approved: false,
        compatibility_notes: String::from(
            "legacy promoted_channel backfill requires an exact compatibility publication before reuse",
        ),
        audit_event_id,
        published_at,
    }
}

fn summarize_promoted_channel(manifests: &[UvmImagePublicationManifest]) -> Option<String> {
    let channels = manifests
        .iter()
        .map(|manifest| manifest.channel.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    if channels.len() == 1 {
        return channels.iter().next().map(|channel| (*channel).to_owned());
    }
    None
}

fn publication_manifest_key(image_id: &str, manifest: &PublicationManifestSelection) -> String {
    format!(
        "{image_id}:{}:{}:{}:{}:{}:{}",
        manifest.channel,
        manifest.host_class,
        manifest.machine_family,
        manifest.guest_profile,
        manifest.region,
        manifest.cell
    )
}

fn publication_manifest_state_fingerprint(
    image_id: &str,
    manifests: &[UvmImagePublicationManifest],
) -> String {
    let manifest_state = manifests
        .iter()
        .map(|manifest| {
            format!(
                "image_id={image_id:?};channel={channel:?};host_class={host_class:?};machine_family={machine_family:?};guest_profile={guest_profile:?};region={region:?};cell={cell:?};compatibility_row_id={compatibility_row_id:?};compatibility_match_key={compatibility_match_key:?};host_family={host_family:?};accelerator_backend={accelerator_backend:?};claim_tier={claim_tier:?};secure_boot_supported={secure_boot_supported};live_migration_supported={live_migration_supported};policy_approved={policy_approved};compatibility_notes={compatibility_notes:?};audit_event_id={audit_event_id:?};published_at={published_at}",
                channel = manifest.channel.as_str(),
                host_class = manifest.host_class.as_str(),
                machine_family = manifest.machine_family.as_str(),
                guest_profile = manifest.guest_profile.as_str(),
                region = manifest.region.as_str(),
                cell = manifest.cell.as_str(),
                compatibility_row_id = manifest
                    .compatibility_row_id
                    .as_ref()
                    .map(|id| id.as_str())
                    .unwrap_or(""),
                compatibility_match_key = manifest.compatibility_match_key.as_str(),
                host_family = manifest.host_family.as_str(),
                accelerator_backend = manifest.accelerator_backend.as_str(),
                claim_tier = manifest.claim_tier.as_str(),
                secure_boot_supported = manifest.secure_boot_supported,
                live_migration_supported = manifest.live_migration_supported,
                policy_approved = manifest.policy_approved,
                compatibility_notes = manifest.compatibility_notes.as_str(),
                audit_event_id = manifest.audit_event_id.as_str(),
                published_at = manifest.published_at.unix_timestamp_nanos(),
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    sha256_hex(format!("uvm-image-publication-state:v2|{manifest_state}").as_bytes())
}

fn normalize_publication_manifest_state(record: &mut UvmImageRecord) -> bool {
    if record.publication_manifests.is_empty() {
        return false;
    }
    let original_manifests = record.publication_manifests.clone();
    let original_promoted_channel = record.promoted_channel.clone();
    sort_publication_manifests(&mut record.publication_manifests);
    record.promoted_channel = summarize_promoted_channel(&record.publication_manifests);
    record.publication_manifests != original_manifests
        || record.promoted_channel != original_promoted_channel
}

fn publication_manifest_fingerprint(image_id: &str, exact_match: &ExactPublicationMatch) -> String {
    sha256_hex(
        format!(
            "uvm-image-publication:v2|{image_id}|{}|{}|{}|{}|{}|{}|{}|{}",
            exact_match.manifest.channel,
            exact_match.manifest.host_class,
            exact_match.manifest.machine_family,
            exact_match.manifest.guest_profile,
            exact_match.manifest.region,
            exact_match.manifest.cell,
            exact_match.row.id.as_str(),
            exact_match.compatibility_match_key,
        )
        .as_bytes(),
    )
}

fn publication_manifest_migration_context() -> Result<RequestContext> {
    Ok(RequestContext::new()?.with_actor(PUBLICATION_MANIFEST_MIGRATOR_ACTOR))
}

fn publication_compatibility_match_key(
    record: &UvmImageRecord,
    manifest: &PublicationManifestSelection,
) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        record.architecture,
        manifest.machine_family,
        manifest.guest_profile,
        record.claim_tier,
        manifest.host_class,
        manifest.region,
        manifest.cell
    )
}

fn build_image_compatibility_requirement(
    architecture: &str,
    machine_family: &str,
    guest_profile: &str,
    preferred_boot_device: &str,
    claim_tier: &str,
) -> Result<UvmCompatibilityRequirement> {
    UvmCompatibilityRequirement::parse_keys(
        GuestArchitecture::parse(architecture)?,
        machine_family,
        guest_profile,
        preferred_boot_device,
        claim_tier,
    )
}

fn build_image_compatibility_evidence(
    source_kind: &str,
    guest_os: &str,
    requirement: &UvmCompatibilityRequirement,
    overlay_policy: Option<&UvmOverlayPolicyRecord>,
) -> Vec<UvmCompatibilityEvidence> {
    let overlay_summary = overlay_policy.map_or_else(
        || String::from("overlay_policy=none"),
        |policy| {
            format!(
                "overlay_policy={} root_mode={} writable_layer_limit={} base_source_kinds={} machine_families={} guest_profiles={} publication_channels={} host_classes={} regions={} cells={}",
                policy.id,
                policy.root_mode,
                policy.writable_layer_limit,
                policy.chain_compatibility.base_source_kinds.join(","),
                policy.chain_compatibility.machine_families.join(","),
                policy.chain_compatibility.guest_profiles.join(","),
                policy.publication.allowed_channels.join(","),
                summarize_overlay_scope_rules(&policy.publication.allowed_host_classes),
                summarize_overlay_scope_rules(&policy.publication.allowed_regions),
                summarize_overlay_scope_rules(&policy.publication.allowed_cells),
            )
        },
    );
    vec![UvmCompatibilityEvidence {
        source: UvmCompatibilityEvidenceSource::ImageContract,
        summary: format!(
            "source_kind={} guest_os={} machine_family={} guest_profile={} boot_device={} {}",
            source_kind,
            guest_os,
            requirement.machine_family.as_str(),
            requirement.guest_profile.as_str(),
            requirement.boot_device.as_str(),
            overlay_summary,
        ),
        evidence_mode: None,
    }]
}

fn compatibility_artifact_summary(row: &UvmCompatibilityReport) -> String {
    format!(
        "compatibility_artifact row_id={} host_class={} region={} cell={} host_family={} accelerator_backend={} machine_family={} guest_profile={} claim_tier={} secure_boot_supported={} live_migration_supported={} policy_approved={} notes={}",
        row.id,
        row.host_class,
        row.region,
        row.cell,
        row.host_family,
        row.accelerator_backend,
        row.machine_family,
        row.guest_profile,
        row.claim_tier,
        row.secure_boot_supported,
        row.live_migration_supported,
        row.policy_approved,
        row.notes,
    )
}

fn compatibility_evidence_state_fingerprint(
    image_id: &str,
    evidence: &[UvmCompatibilityEvidence],
) -> String {
    let evidence_state = evidence
        .iter()
        .map(|row| {
            format!(
                "source={};summary={};evidence_mode={}",
                row.source.as_str(),
                row.summary,
                row.evidence_mode.as_deref().unwrap_or(""),
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    sha256_hex(
        format!("uvm-image-compatibility-evidence:v1|{image_id}|{evidence_state}").as_bytes(),
    )
}

fn summarize_overlay_scope_rules(values: &[String]) -> String {
    if values.is_empty() {
        return String::from("*");
    }
    values.join(",")
}

fn ensure_overlay_policy_supports_image(
    policy: &UvmOverlayPolicyRecord,
    source_kind: &str,
    machine_family: &str,
    guest_profile: &str,
) -> Result<()> {
    let mut blockers = Vec::new();
    if !policy
        .chain_compatibility
        .base_source_kinds
        .iter()
        .any(|value| value == source_kind)
    {
        blockers.push(format!("source_kind `{source_kind}`"));
    }
    if !policy
        .chain_compatibility
        .machine_families
        .iter()
        .any(|value| value == machine_family)
    {
        blockers.push(format!("machine_family `{machine_family}`"));
    }
    if !policy
        .chain_compatibility
        .guest_profiles
        .iter()
        .any(|value| value == guest_profile)
    {
        blockers.push(format!("guest_profile `{guest_profile}`"));
    }
    if blockers.is_empty() {
        return Ok(());
    }
    Err(PlatformError::conflict(format!(
        "overlay policy `{}` does not support {}",
        policy.id,
        blockers.join(", ")
    )))
}

fn ensure_overlay_policy_supports_publication(
    policy: &UvmOverlayPolicyRecord,
    manifest: &PublicationManifestSelection,
) -> Result<()> {
    if !policy
        .publication
        .allowed_channels
        .iter()
        .any(|value| value == &manifest.channel)
    {
        return Err(PlatformError::conflict(format!(
            "overlay policy `{}` does not allow promotion channel `{}`",
            policy.id, manifest.channel
        )));
    }
    if !policy.publication.allowed_host_classes.is_empty()
        && !policy
            .publication
            .allowed_host_classes
            .iter()
            .any(|value| value == &manifest.host_class)
    {
        return Err(PlatformError::conflict(format!(
            "overlay policy `{}` does not allow host_class `{}`",
            policy.id, manifest.host_class
        )));
    }
    if !policy.publication.allowed_regions.is_empty()
        && !policy
            .publication
            .allowed_regions
            .iter()
            .any(|value| value == &manifest.region)
    {
        return Err(PlatformError::conflict(format!(
            "overlay policy `{}` does not allow region `{}`",
            policy.id, manifest.region
        )));
    }
    if !policy.publication.allowed_cells.is_empty()
        && !policy
            .publication
            .allowed_cells
            .iter()
            .any(|value| value == &manifest.cell)
    {
        return Err(PlatformError::conflict(format!(
            "overlay policy `{}` does not allow cell `{}`",
            policy.id, manifest.cell
        )));
    }
    Ok(())
}

fn normalize_compatibility_row(value: &UvmCompatibilityReport) -> Result<UvmCompatibilityReport> {
    let host_family = normalize_host_family(&value.host_family)?;
    let guest_architecture = normalize_architecture(&value.guest_architecture)?;
    let accelerator_backend = normalize_backend_key(&value.accelerator_backend)?;
    let machine_family = normalize_machine_family(&value.machine_family)?;
    let guest_profile = normalize_guest_profile(&value.guest_profile)?;
    let claim_tier = normalize_claim_tier(&value.claim_tier)?;
    let host_class = if value.host_class.trim().is_empty() {
        derive_compatibility_host_class_key(&host_family, &accelerator_backend, &guest_architecture)
    } else {
        normalize_host_class(&value.host_class)?
    };
    Ok(UvmCompatibilityReport {
        id: value.id.clone(),
        host_class,
        region: normalize_publication_scope(&value.region, "region")?,
        cell: normalize_publication_scope(&value.cell, "cell")?,
        host_family,
        guest_architecture,
        accelerator_backend,
        machine_family,
        guest_profile,
        secure_boot_supported: value.secure_boot_supported,
        live_migration_supported: value.live_migration_supported,
        policy_approved: value.policy_approved,
        claim_tier,
        notes: normalize_notes(&value.notes)?,
    })
}

fn compatibility_variant_key(row: &UvmCompatibilityReport) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        row.host_class,
        row.region,
        row.cell,
        row.host_family,
        row.guest_architecture,
        row.accelerator_backend,
        row.machine_family,
        row.guest_profile,
        row.claim_tier
    )
}

fn compatibility_revision_key(variant_key: &str, revision: u64) -> String {
    format!("{variant_key}@{revision}")
}

fn normalize_channel(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "stable" | "canary" | "preview" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "channel must be `stable`, `canary`, or `preview`",
        )),
    }
}

fn normalize_region_cell_policy_mode(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "sovereign" | "degraded" => Ok(normalized),
        _ => Err(PlatformError::invalid(
            "policy_mode must be `sovereign` or `degraded`",
        )),
    }
}

fn normalize_region_cell_policy_scopes(values: Vec<String>, field: &str) -> Result<Vec<String>> {
    let mut normalized = values
        .into_iter()
        .map(|value| normalize_publication_scope(&value, field))
        .collect::<Result<Vec<_>>>()?;
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn normalize_region_cell_policy_notes(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PlatformError::invalid(
            "region/cell policy notes may not be empty",
        ));
    }
    if trimmed.len() > 512 {
        return Err(PlatformError::invalid(
            "region/cell policy notes exceed 512 bytes",
        ));
    }
    if trimmed.chars().any(|character| character.is_control()) {
        return Err(PlatformError::invalid(
            "region/cell policy notes may not contain control characters",
        ));
    }
    Ok(trimmed.to_owned())
}

fn normalize_host_class(value: &str) -> Result<String> {
    HostClass::parse(value).map(HostClass::into_string)
}

fn normalize_publication_scope(value: &str, field: &str) -> Result<String> {
    normalize_publication_key(value, field, true)
}

fn normalize_publication_key(value: &str, field: &str, allow_colon: bool) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(PlatformError::invalid(format!("{field} may not be empty")));
    }
    if normalized.len() > 128 {
        return Err(PlatformError::invalid(format!("{field} exceeds 128 bytes")));
    }
    let is_valid = normalized.chars().all(|character| {
        character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '_' | '.')
            || (allow_colon && character == ':')
    });
    if !is_valid {
        return Err(PlatformError::invalid(format!(
            "{field} may only contain lowercase ascii letters, digits, dots, dashes, underscores{}",
            if allow_colon { ", and colons" } else { "" }
        )));
    }
    Ok(normalized)
}

fn is_apple_guest_os(guest_os: &str) -> bool {
    guest_os.contains("macos") || guest_os.contains("ios")
}

#[cfg(test)]
mod tests {
    use http::StatusCode;
    use http_body_util::BodyExt;
    use std::path::PathBuf;
    use tempfile::TempDir;

    use super::{
        CreateFirmwareBundleRequest, CreateFirmwareSignerLineageEntryRequest,
        CreateGuestProfileRequest, CreateOverlayPolicyRequest, CreateRegionCellPolicyRequest,
        ImportImageRequest, PromoteImageRequest, UvmArtifactAttestationKind,
        UvmCompatibilityReport, UvmFirmwareBundleRecord, UvmGuestProfileRecord,
        UvmImagePublicationManifest, UvmImageRecord, UvmImageService,
        UvmOverlayChainCompatibilityRules, UvmOverlayPolicyRecord, UvmOverlayPublicationRules,
        UvmRegionCellPolicyRecord, VerifyImageRequest,
    };
    use uhost_core::RequestContext;
    use uhost_types::{AuditId, UvmCompatibilityReportId};
    use uhost_uvm::{
        BootDevice, ClaimTier, GuestArchitecture, GuestProfile, MachineFamily,
        UvmCompatibilityEvidenceSource, UvmCompatibilityRequirement, UvmExecutionIntent,
    };

    async fn test_service() -> (TempDir, UvmImageService, RequestContext) {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));
        (temp, service, context)
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

    fn promote_request(channel: &str) -> PromoteImageRequest {
        PromoteImageRequest {
            channel: String::from(channel),
            host_class: None,
            machine_family: None,
            guest_profile: None,
            region: None,
            cell: None,
        }
    }

    fn compatibility_row(
        machine_family: &str,
        guest_profile: &str,
        notes: &str,
    ) -> UvmCompatibilityReport {
        UvmCompatibilityReport {
            id: UvmCompatibilityReportId::generate().unwrap_or_else(|error| panic!("{error}")),
            host_class: super::derive_compatibility_host_class_key(
                "linux",
                "software_dbt",
                "x86_64",
            ),
            region: super::default_region_key(),
            cell: super::default_cell_key(),
            host_family: String::from("linux"),
            guest_architecture: String::from("x86_64"),
            accelerator_backend: String::from("software_dbt"),
            machine_family: String::from(machine_family),
            guest_profile: String::from(guest_profile),
            secure_boot_supported: false,
            live_migration_supported: false,
            policy_approved: true,
            claim_tier: String::from("compatible"),
            notes: String::from(notes),
        }
    }

    fn scoped_compatibility_row(
        host_class: &str,
        region: &str,
        cell: &str,
        machine_family: &str,
        guest_profile: &str,
        claim_tier: &str,
        notes: &str,
    ) -> UvmCompatibilityReport {
        let mut row = compatibility_row(machine_family, guest_profile, notes);
        row.host_class = String::from(host_class);
        row.region = String::from(region);
        row.cell = String::from(cell);
        row.claim_tier = String::from(claim_tier);
        row
    }

    fn publication_manifest(
        channel: &str,
        host_class: &str,
        region: &str,
        cell: &str,
        compatibility_row_id: Option<&str>,
        compatibility_match_key: &str,
        audit_event_id: &str,
        published_at: i64,
    ) -> UvmImagePublicationManifest {
        let has_exact_match = compatibility_row_id.is_some();
        UvmImagePublicationManifest {
            channel: String::from(channel),
            host_class: String::from(host_class),
            machine_family: String::from("general_purpose_pci"),
            guest_profile: String::from("linux_standard"),
            region: String::from(region),
            cell: String::from(cell),
            compatibility_row_id: compatibility_row_id.map(|value| {
                UvmCompatibilityReportId::parse(value).unwrap_or_else(|error| panic!("{error}"))
            }),
            compatibility_match_key: String::from(compatibility_match_key),
            host_family: if has_exact_match {
                String::from("linux")
            } else {
                String::new()
            },
            accelerator_backend: if has_exact_match {
                String::from("software_dbt")
            } else {
                String::new()
            },
            claim_tier: String::from("compatible"),
            secure_boot_supported: has_exact_match,
            live_migration_supported: false,
            policy_approved: has_exact_match,
            compatibility_notes: if has_exact_match {
                String::from("exact publication manifest")
            } else {
                String::from("legacy fallback publication manifest")
            },
            audit_event_id: AuditId::parse(audit_event_id)
                .unwrap_or_else(|error| panic!("{error}")),
            published_at: time::OffsetDateTime::from_unix_timestamp(published_at)
                .unwrap_or_else(|error| panic!("{error}")),
        }
    }

    #[tokio::test]
    async fn apple_guest_import_requires_license_token() {
        let (_temp, service, context) = test_service().await;

        let error = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("iso"),
                    source_uri: String::from("file:///images/macos.iso"),
                    guest_os: String::from("macos-14"),
                    architecture: String::from("aarch64"),
                    digest: None,
                    signature_attestation: None,
                    provenance_attestation: None,
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected legal token rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn import_and_verify_canonicalize_inputs() {
        let (_temp, service, context) = test_service().await;
        let digest = "A".repeat(64);

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from(" RAW "),
                    source_uri: String::from("HTTPS://images.example.com/base.raw"),
                    guest_os: String::from("Ubuntu-24.04"),
                    architecture: String::from("X86_64"),
                    digest: Some(digest.clone()),
                    signature_attestation: Some(String::from("sigstore-bundle")),
                    provenance_attestation: Some(String::from("provenance-manifest")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);
        let record: UvmImageRecord = response_json(created).await;
        assert_eq!(record.source_kind, "raw");
        assert_eq!(record.source_uri, "https://images.example.com/base.raw");
        assert_eq!(record.guest_os, "ubuntu-24.04");
        assert_eq!(record.architecture, "x86_64");
        assert_eq!(record.digest, digest.to_ascii_lowercase());
        assert!(!record.install_media);
        assert_eq!(record.preferred_boot_device, "disk");
        assert!(super::image_has_attestation_kind(
            &record,
            UvmArtifactAttestationKind::Signature
        ));
        assert!(super::image_has_attestation_kind(
            &record,
            UvmArtifactAttestationKind::Provenance
        ));
        assert_eq!(record.attestations.len(), 2);
        assert!(!record.verified);
    }

    #[tokio::test]
    async fn iso_import_defaults_to_cdrom_boot_preference() {
        let (_temp, service, context) = test_service().await;

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("iso"),
                    source_uri: String::from("file:///images/ubuntu-26.04.iso"),
                    guest_os: String::from("ubuntu-26.04"),
                    architecture: String::from("x86_64"),
                    digest: Some("c".repeat(64)),
                    signature_attestation: None,
                    provenance_attestation: None,
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let record: UvmImageRecord = response_json(created).await;
        assert!(record.install_media);
        assert_eq!(record.preferred_boot_device, "cdrom");
        assert_eq!(record.source_kind, "iso");
    }

    #[tokio::test]
    async fn import_emits_compatibility_requirement_and_evidence() {
        let (_temp, service, context) = test_service().await;

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("object://images/linux-base.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("d".repeat(64)),
                    signature_attestation: Some(String::from("sigstore-bundle")),
                    provenance_attestation: Some(String::from("provenance-manifest")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let record: UvmImageRecord = response_json(created).await;
        let expected = UvmCompatibilityRequirement::new(
            GuestArchitecture::X86_64,
            MachineFamily::GeneralPurposePci,
            GuestProfile::LinuxStandard,
            BootDevice::Disk,
            ClaimTier::Compatible,
        );

        assert_eq!(record.compatibility_requirement.as_ref(), Some(&expected));
        assert_eq!(
            record.execution_intent,
            UvmExecutionIntent::default_for_guest_profile(GuestProfile::LinuxStandard)
        );
        assert!(record.compatibility_evidence.iter().any(|row| {
            row.source == UvmCompatibilityEvidenceSource::ImageContract
                && row.summary.contains("source_kind=raw")
        }));
        assert!(record.compatibility_evidence.iter().any(|row| {
            row.source == UvmCompatibilityEvidenceSource::ImageContract
                && row.summary.contains("compatibility_artifact")
                && row.summary.contains("host_class=linux-software_dbt-x86_64")
                && row.summary.contains("region=global")
                && row.summary.contains("cell=global")
                && row.summary.contains("policy_approved=true")
        }));
    }

    #[tokio::test]
    async fn reopen_refreshes_scoped_compatibility_artifacts_from_matrix_rows() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/scoped-artifact-refresh.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("5".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;

        let scoped_row = scoped_compatibility_row(
            "isolated_kvm",
            "us-east1",
            "us-east1:cell-a",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Scoped compatibility artifact refresh row",
        );
        let scoped_row_id = scoped_row.id.clone();
        service
            .compatibility
            .create(&super::compatibility_variant_key(&scoped_row), scoped_row)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let refreshed = reopened
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing refreshed image"));

        assert!(refreshed.value.compatibility_evidence.iter().any(|row| {
            row.source == UvmCompatibilityEvidenceSource::ImageContract
                && row.summary.contains("compatibility_artifact")
                && row
                    .summary
                    .contains(format!("row_id={scoped_row_id}").as_str())
                && row.summary.contains("host_class=isolated_kvm")
                && row.summary.contains("region=us-east1")
                && row.summary.contains("cell=us-east1:cell-a")
        }));
    }

    #[tokio::test]
    async fn verify_requires_required_evidence() {
        let (_temp, service, context) = test_service().await;
        let digest = "B".repeat(64);

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/base.raw"),
                    guest_os: String::from("ubuntu-24.04"),
                    architecture: String::from("x86_64"),
                    digest: Some(digest.clone()),
                    signature_attestation: None,
                    provenance_attestation: None,
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;

        let error = service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some(digest.to_ascii_uppercase()),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_err();

        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "signature evidence is required before verification"
        );
    }

    #[tokio::test]
    async fn verify_then_promote_requires_provenance_and_signature_evidence() {
        let (_temp, service, context) = test_service().await;
        let digest = "c".repeat(64);

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/base.raw"),
                    guest_os: String::from("ubuntu-24.04"),
                    architecture: String::from("x86_64"),
                    digest: Some(digest.clone()),
                    signature_attestation: None,
                    provenance_attestation: None,
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;

        let verified = service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some(digest.clone()),
                    require_signature: Some(false),
                    require_provenance: Some(false),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(verified.status(), StatusCode::OK);

        let error = service
            .promote_image(image.id.as_str(), promote_request("stable"), &context)
            .await
            .unwrap_err();

        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "image must have signature and provenance evidence before promotion"
        );
    }

    #[tokio::test]
    async fn deterministic_listings_are_sorted() {
        let (_temp, service, context) = test_service().await;

        let first = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/z-last.raw"),
                    guest_os: String::from("ubuntu-24.04"),
                    architecture: String::from("x86_64"),
                    digest: Some("d".repeat(64)),
                    signature_attestation: Some(String::from("sig-a")),
                    provenance_attestation: Some(String::from("prov-a")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let second = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/a-first.raw"),
                    guest_os: String::from("ubuntu-24.04"),
                    architecture: String::from("x86_64"),
                    digest: Some("e".repeat(64)),
                    signature_attestation: Some(String::from("sig-b")),
                    provenance_attestation: Some(String::from("prov-b")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), StatusCode::CREATED);
        assert_eq!(second.status(), StatusCode::CREATED);

        let images = service
            .list_images()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            images
                .into_iter()
                .map(|record| record.source_uri)
                .collect::<Vec<_>>(),
            vec![
                String::from("s3://artifacts/a-first.raw"),
                String::from("s3://artifacts/z-last.raw"),
            ]
        );

        let rows = service
            .list_compatibility_rows()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            rows.iter()
                .map(|row| (
                    row.host_family.as_str(),
                    row.guest_architecture.as_str(),
                    row.accelerator_backend.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("dragonflybsd", "x86_64", "bhyve"),
                ("freebsd", "x86_64", "bhyve"),
                ("linux", "aarch64", "kvm"),
                ("linux", "aarch64", "software_dbt"),
                ("linux", "x86_64", "kvm"),
                ("linux", "x86_64", "software_dbt"),
                ("macos", "aarch64", "apple_virtualization"),
                ("netbsd", "x86_64", "bhyve"),
                ("openbsd", "x86_64", "bhyve"),
                ("windows", "x86_64", "hyperv_whp"),
            ]
        );
    }

    #[tokio::test]
    async fn verify_then_promote_flow() {
        let (_temp, service, context) = test_service().await;
        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/base.raw"),
                    guest_os: String::from("ubuntu-24.04"),
                    architecture: String::from("x86_64"),
                    digest: Some("f".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(created.status(), StatusCode::CREATED);
        let image_id = service
            .images
            .list()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .first()
            .map(|(_, value)| value.value.id.to_string())
            .unwrap_or_else(|| panic!("missing image"));

        let verified = service
            .verify_image(
                &image_id,
                VerifyImageRequest {
                    expected_digest: Some("f".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(verified.status(), StatusCode::OK);

        let promoted = service
            .promote_image(&image_id, promote_request("stable"), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(promoted.status(), StatusCode::OK);
        let promoted_record: UvmImageRecord = response_json(promoted).await;
        assert_eq!(promoted_record.promoted_channel.as_deref(), Some("stable"));
        assert_eq!(promoted_record.publication_manifests.len(), 1);
        let manifest = &promoted_record.publication_manifests[0];
        assert_eq!(manifest.channel, "stable");
        assert_eq!(manifest.host_class, "linux-software_dbt-x86_64");
        assert_eq!(manifest.machine_family, promoted_record.machine_family);
        assert_eq!(manifest.guest_profile, promoted_record.guest_profile);
        assert_eq!(manifest.region, "global");
        assert_eq!(manifest.cell, "global");
        assert!(manifest.compatibility_row_id.is_some());
        assert_eq!(
            manifest.compatibility_match_key,
            "x86_64:general_purpose_pci:linux_standard:compatible:linux-software_dbt-x86_64:global:global"
        );
        assert!(!manifest.audit_event_id.as_str().is_empty());
    }

    #[tokio::test]
    async fn reopen_dedupes_publication_manifests_by_tuple_and_keeps_authoritative_state() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/dedupe.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("d".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("d".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored image"));
        let mut duplicated = stored.value.clone();
        duplicated.promoted_channel = Some(String::from("preview"));
        duplicated.publication_manifests = vec![
            publication_manifest(
                "stable",
                "linux-software_dbt-x86_64",
                "global",
                "global",
                None,
                "",
                "aud_fallbacklatest",
                50,
            ),
            publication_manifest(
                "stable",
                "linux-software_dbt-x86_64",
                "global",
                "global",
                Some("ucr_middle"),
                "middle-match",
                "aud_middle",
                20,
            ),
            publication_manifest(
                "stable",
                "linux-software_dbt-x86_64",
                "global",
                "global",
                Some("ucr_latest"),
                "latest-match",
                "aud_latest",
                30,
            ),
            publication_manifest(
                "stable",
                "isolated_kvm",
                "us-east1",
                "us-east1:cell-a",
                Some("ucr_cella"),
                "cell-match",
                "aud_cella",
                40,
            ),
        ];
        duplicated
            .metadata
            .touch(String::from("duplicate-publication-manifests"));
        service
            .images
            .upsert(image.id.as_str(), duplicated, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let normalized = reopened
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing normalized image"));

        assert_eq!(normalized.value.promoted_channel.as_deref(), Some("stable"));
        assert_eq!(normalized.value.publication_manifests.len(), 2);
        let default_manifest = normalized
            .value
            .publication_manifests
            .iter()
            .find(|manifest| {
                manifest.channel == "stable"
                    && manifest.host_class == "linux-software_dbt-x86_64"
                    && manifest.region == "global"
                    && manifest.cell == "global"
            })
            .unwrap_or_else(|| panic!("missing default manifest"));
        assert_eq!(
            default_manifest
                .compatibility_row_id
                .as_ref()
                .map(|id| id.as_str()),
            Some("ucr_latest")
        );
        assert_eq!(default_manifest.compatibility_match_key, "latest-match");
        assert_eq!(default_manifest.audit_event_id.as_str(), "aud_latest");
        assert!(default_manifest.policy_approved);
        assert!(
            normalized
                .value
                .publication_manifests
                .iter()
                .any(|manifest| {
                    manifest.channel == "stable"
                        && manifest.host_class == "isolated_kvm"
                        && manifest.region == "us-east1"
                        && manifest.cell == "us-east1:cell-a"
                })
        );
    }

    #[tokio::test]
    async fn duplicate_import_is_idempotent_and_enriches_attestation_flags() {
        let (_temp, service, context) = test_service().await;
        let first = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("qcow2"),
                    source_uri: String::from("registry://images/ubuntu-base.qcow2"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("1".repeat(64)),
                    signature_attestation: None,
                    provenance_attestation: None,
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_record: UvmImageRecord = response_json(first).await;
        assert!(first_record.attestations.is_empty());

        let second = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("qcow2"),
                    source_uri: String::from("registry://images/ubuntu-base.qcow2"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("1".repeat(64)),
                    signature_attestation: Some(String::from("sig-v1")),
                    provenance_attestation: Some(String::from("prov-v1")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(second.status(), StatusCode::OK);
        let second_record: UvmImageRecord = response_json(second).await;
        assert_eq!(first_record.id, second_record.id);
        assert!(super::image_has_attestation_kind(
            &second_record,
            UvmArtifactAttestationKind::Signature
        ));
        assert!(super::image_has_attestation_kind(
            &second_record,
            UvmArtifactAttestationKind::Provenance
        ));
        let images = service
            .list_images()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(images.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_content_from_different_uri_is_rejected() {
        let (_temp, service, context) = test_service().await;
        service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("qcow2"),
                    source_uri: String::from("registry://images/ubuntu-base-a.qcow2"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("2".repeat(64)),
                    signature_attestation: Some(String::from("sig-v1")),
                    provenance_attestation: Some(String::from("prov-v1")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("qcow2"),
                    source_uri: String::from("registry://images/ubuntu-base-b.qcow2"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("2".repeat(64)),
                    signature_attestation: Some(String::from("sig-v2")),
                    provenance_attestation: Some(String::from("prov-v2")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected duplicate content conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn verify_and_promote_are_idempotent_for_same_target_state() {
        let (_temp, service, context) = test_service().await;
        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/base.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("3".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;

        let verified = service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("3".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(verified.status(), StatusCode::OK);
        let after_first_verify = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .len();
        let verified_again = service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("3".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(verified_again.status(), StatusCode::OK);
        let after_second_verify = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .len();
        assert_eq!(after_first_verify, after_second_verify);

        let promoted = service
            .promote_image(image.id.as_str(), promote_request("stable"), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(promoted.status(), StatusCode::OK);
        let after_first_promote = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .len();
        let promoted_again = service
            .promote_image(image.id.as_str(), promote_request("stable"), &context)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(promoted_again.status(), StatusCode::OK);
        let after_second_promote = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .len();
        assert_eq!(after_first_promote, after_second_promote);

        let variant_row = scoped_compatibility_row(
            "isolated_kvm",
            "us-east1",
            "us-east1:cell-a",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Cell-scoped isolated KVM publication path",
        );
        let variant_key = super::compatibility_variant_key(&variant_row);
        service
            .compatibility
            .create(&variant_key, variant_row)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let promoted_variant = service
            .promote_image(
                image.id.as_str(),
                PromoteImageRequest {
                    channel: String::from("canary"),
                    host_class: Some(String::from("isolated_kvm")),
                    machine_family: None,
                    guest_profile: None,
                    region: Some(String::from("us-east1")),
                    cell: Some(String::from("us-east1:cell-a")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let variant_record: UvmImageRecord = response_json(promoted_variant).await;
        assert_eq!(variant_record.promoted_channel, None);
        assert_eq!(variant_record.publication_manifests.len(), 2);
        assert!(variant_record.publication_manifests.iter().any(|manifest| {
            manifest.channel == "stable"
                && manifest.host_class == "linux-software_dbt-x86_64"
                && manifest.region == "global"
                && manifest.cell == "global"
        }));
        assert!(variant_record.publication_manifests.iter().any(|manifest| {
            manifest.channel == "canary"
                && manifest.host_class == "isolated_kvm"
                && manifest.region == "us-east1"
                && manifest.cell == "us-east1:cell-a"
                && manifest.compatibility_match_key
                    == "x86_64:general_purpose_pci:linux_standard:compatible:isolated_kvm:us-east1:us-east1:cell-a"
        }));
    }

    #[tokio::test]
    async fn promote_emits_exact_row_publication_artifact_for_scoped_target() {
        let (_temp, service, context) = test_service().await;
        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/scoped-publication.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("4".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("4".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let scoped_row = scoped_compatibility_row(
            "isolated_kvm",
            "us-east1",
            "us-east1:cell-a",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Cell-scoped exact publication artifact",
        );
        let scoped_row_id = scoped_row.id.clone();
        service
            .compatibility
            .create(&super::compatibility_variant_key(&scoped_row), scoped_row)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let promoted = service
            .promote_image(
                image.id.as_str(),
                PromoteImageRequest {
                    channel: String::from("canary"),
                    host_class: Some(String::from("isolated_kvm")),
                    machine_family: None,
                    guest_profile: None,
                    region: Some(String::from("us-east1")),
                    cell: Some(String::from("us-east1:cell-a")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let promoted_record: UvmImageRecord = response_json(promoted).await;
        let manifest = promoted_record
            .publication_manifests
            .iter()
            .find(|manifest| {
                manifest.channel == "canary"
                    && manifest.host_class == "isolated_kvm"
                    && manifest.region == "us-east1"
                    && manifest.cell == "us-east1:cell-a"
            })
            .unwrap_or_else(|| panic!("missing scoped publication manifest"));
        let expected_publication_manifest_key = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            image.id,
            manifest.channel,
            manifest.host_class,
            manifest.machine_family,
            manifest.guest_profile,
            manifest.region,
            manifest.cell
        );
        let expected_compatibility_match_key = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            promoted_record.architecture,
            manifest.machine_family,
            manifest.guest_profile,
            promoted_record.claim_tier,
            manifest.host_class,
            manifest.region,
            manifest.cell
        );

        let promoted_event = service
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .into_iter()
            .find(|message| message.payload.header.event_type == "uvm.image.promoted.v1")
            .unwrap_or_else(|| panic!("missing promotion outbox artifact"));
        if let uhost_types::EventPayload::Service(event) = &promoted_event.payload.payload {
            assert_eq!(event.resource_kind, "uvm_image");
            assert_eq!(event.resource_id, image.id.as_str());
            assert_eq!(event.action, "promoted");
            assert_eq!(event.details["channel"], serde_json::json!("canary"));
            assert_eq!(
                event.details["publication_manifest_key"],
                serde_json::json!(expected_publication_manifest_key)
            );
            assert_eq!(
                event.details["host_class"],
                serde_json::json!("isolated_kvm")
            );
            assert_eq!(
                event.details["machine_family"],
                serde_json::json!(manifest.machine_family.as_str())
            );
            assert_eq!(
                event.details["guest_profile"],
                serde_json::json!(manifest.guest_profile.as_str())
            );
            assert_eq!(event.details["region"], serde_json::json!("us-east1"));
            assert_eq!(event.details["cell"], serde_json::json!("us-east1:cell-a"));
            assert_eq!(
                event.details["compatibility_row_id"],
                serde_json::json!(scoped_row_id.as_str())
            );
            assert_eq!(
                event.details["compatibility_match_key"],
                serde_json::json!(expected_compatibility_match_key)
            );
        } else {
            panic!("expected service payload");
        }
        assert_eq!(
            manifest.compatibility_row_id.as_ref(),
            Some(&scoped_row_id),
            "manifest should retain the exact matched compatibility row id",
        );
        assert_eq!(
            manifest.compatibility_match_key,
            expected_compatibility_match_key
        );
        assert_eq!(
            manifest.audit_event_id,
            promoted_event.payload.header.event_id
        );
        assert!(promoted_record.compatibility_evidence.iter().any(|row| {
            row.source == UvmCompatibilityEvidenceSource::ImageContract
                && row.summary.contains("compatibility_artifact")
                && row
                    .summary
                    .contains(format!("row_id={scoped_row_id}").as_str())
                && row.summary.contains("host_class=isolated_kvm")
                && row.summary.contains("region=us-east1")
                && row.summary.contains("cell=us-east1:cell-a")
                && row.evidence_mode.as_deref() == Some("policy_approved")
        }));
    }

    #[tokio::test]
    async fn promote_rejects_variant_overrides_until_variant_matrix_revisions_land() {
        let (_temp, service, context) = test_service().await;
        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/variant.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("6".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("6".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .promote_image(
                image.id.as_str(),
                PromoteImageRequest {
                    channel: String::from("stable"),
                    host_class: Some(String::from("isolated_kvm")),
                    machine_family: Some(String::from("microvm_linux")),
                    guest_profile: None,
                    region: None,
                    cell: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected machine-family conflict"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "promotion manifest machine_family must match the image contract until variant matrix revisions land"
        );
    }

    #[tokio::test]
    async fn promote_requires_exact_compatibility_row_for_host_class_region_and_cell() {
        let (_temp, service, context) = test_service().await;
        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/exact-match.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("7".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("7".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .promote_image(
                image.id.as_str(),
                PromoteImageRequest {
                    channel: String::from("preview"),
                    host_class: Some(String::from("isolated_kvm")),
                    machine_family: None,
                    guest_profile: None,
                    region: Some(String::from("us-east1")),
                    cell: Some(String::from("us-east1:cell-b")),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected exact-row compatibility rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
        assert_eq!(
            error.message,
            "no exact compatibility row matches architecture `x86_64` machine_family `general_purpose_pci` guest_profile `linux_standard` claim_tier `compatible` host_class `isolated_kvm` region `us-east1` cell `us-east1:cell-b`"
        );
    }

    #[tokio::test]
    async fn source_uri_and_digest_validation_are_strict() {
        assert!(super::normalize_source_uri("relative/path/image.raw").is_err());
        assert!(super::normalize_source_uri("file://../escape.raw").is_err());
        assert!(super::normalize_source_uri("file:///safe/path/image.raw").is_ok());
        assert!(super::normalize_digest(Some(format!("sha256:{}", "a".repeat(64)))).is_ok());
    }

    #[tokio::test]
    async fn resolve_verified_image_artifact_path_exposes_local_file_only_when_verified() {
        let (_temp, service, context) = test_service().await;
        let digest = "a".repeat(64);

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///tmp/verified.img"),
                    guest_os: String::from("ubuntu-24.04"),
                    architecture: String::from("x86_64"),
                    digest: Some(digest.clone()),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let record: UvmImageRecord = response_json(created).await;

        service
            .verify_image(
                record.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some(digest),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let path = service
            .resolve_verified_image_artifact_path(record.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path, PathBuf::from("/tmp/verified.img"));

        let remote_created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://bucket/artifact.raw"),
                    guest_os: String::from("ubuntu-24.04"),
                    architecture: String::from("x86_64"),
                    digest: Some("b".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let remote_record: UvmImageRecord = response_json(remote_created).await;

        service
            .verify_image(
                remote_record.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("b".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let error = service
            .resolve_verified_image_artifact_path(remote_record.id.as_str())
            .await
            .err()
            .unwrap_or_else(|| panic!("expected remote artifact rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert!(
            error.message.contains("file:// scheme"),
            "unexpected error message: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn resolve_verified_firmware_artifact_path_requires_local_verified_bundle() {
        let (_temp, service, context) = test_service().await;

        let created = service
            .create_firmware_bundle(
                CreateFirmwareBundleRequest {
                    name: String::from("local-fw"),
                    architecture: String::from("x86_64"),
                    firmware_profile: String::from("uefi_standard"),
                    artifact_uri: String::from("file:///tmp/fw.bin"),
                    secure_boot_capable: Some(false),
                    verified: Some(true),
                    secure_boot_posture: None,
                    signer_lineage: Vec::new(),
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let record: UvmFirmwareBundleRecord = response_json(created).await;

        let path = service
            .resolve_verified_firmware_artifact_path(record.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path, PathBuf::from("/tmp/fw.bin"));

        let unverified = service
            .create_firmware_bundle(
                CreateFirmwareBundleRequest {
                    name: String::from("remote-fw"),
                    architecture: String::from("x86_64"),
                    firmware_profile: String::from("uefi_standard"),
                    artifact_uri: String::from("https://firmware.example/bin"),
                    secure_boot_capable: Some(false),
                    verified: Some(true),
                    secure_boot_posture: None,
                    signer_lineage: Vec::new(),
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let remote_record: UvmFirmwareBundleRecord = response_json(unverified).await;

        let error = service
            .resolve_verified_firmware_artifact_path(remote_record.id.as_str())
            .await
            .err()
            .unwrap_or_else(|| panic!("expected remote firmware rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
    }

    #[tokio::test]
    async fn default_compatibility_rows_exist() {
        let (_temp, service, _context) = test_service().await;
        let rows = service
            .list_compatibility_rows()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!rows.is_empty());
        assert!(
            rows.iter()
                .filter(|row| row.accelerator_backend == "bhyve")
                .all(|row| !row.secure_boot_supported)
        );
    }

    #[test]
    fn compatibility_variant_key_tracks_host_class_region_and_cell_scope() {
        let east = scoped_compatibility_row(
            "isolated_kvm",
            "us-east1",
            "us-east1:cell-a",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Scoped east variant",
        );
        let west = scoped_compatibility_row(
            "isolated_kvm",
            "us-west1",
            "us-west1:cell-b",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Scoped west variant",
        );
        let edge = scoped_compatibility_row(
            "edge",
            "us-east1",
            "us-east1:cell-a",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Scoped east edge variant",
        );

        let east_key = super::compatibility_variant_key(&east);
        assert_eq!(
            east_key,
            "isolated_kvm:us-east1:us-east1:cell-a:linux:x86_64:software_dbt:general_purpose_pci:linux_standard:compatible"
        );
        assert_ne!(east_key, super::compatibility_variant_key(&west));
        assert_ne!(east_key, super::compatibility_variant_key(&edge));
    }

    #[tokio::test]
    async fn compatibility_integrity_rekeys_legacy_rows_on_full_variant_tuple() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let legacy_key = "legacy-linux-x86-software-dbt";
        let legacy_row = compatibility_row(
            "microvm_linux",
            "linux_direct_kernel",
            "Legacy direct-kernel software variant",
        );
        let variant_key = super::compatibility_variant_key(&legacy_row);

        service
            .compatibility
            .create(legacy_key, legacy_row.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let rows = reopened
            .list_compatibility_rows()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert!(rows.iter().any(|row| {
            row.host_family == "linux"
                && row.guest_architecture == "x86_64"
                && row.accelerator_backend == "software_dbt"
                && row.machine_family == "general_purpose_pci"
                && row.guest_profile == "linux_standard"
        }));
        assert!(rows.iter().any(|row| {
            row.host_family == "linux"
                && row.guest_architecture == "x86_64"
                && row.accelerator_backend == "software_dbt"
                && row.machine_family == "microvm_linux"
                && row.guest_profile == "linux_direct_kernel"
        }));

        let migrated = reopened
            .compatibility
            .get(&variant_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing re-keyed compatibility row"));
        assert!(!migrated.deleted);
        assert_eq!(migrated.value, legacy_row);

        let legacy = reopened
            .compatibility
            .get(legacy_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing legacy compatibility row"));
        assert!(legacy.deleted);
    }

    #[tokio::test]
    async fn compatibility_revisions_persist_tuple_lineage() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let legacy_key = "legacy-linux-x86-software-dbt";
        let legacy_row = compatibility_row(
            "microvm_linux",
            "linux_direct_kernel",
            "Legacy direct-kernel software variant",
        );
        let variant_key = super::compatibility_variant_key(&legacy_row);

        service
            .compatibility
            .create(legacy_key, legacy_row.clone())
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let stored = reopened
            .compatibility
            .get(&variant_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing canonical compatibility row"));
        let mut updated = stored.value.clone();
        updated.notes = String::from("Updated direct-kernel software variant");

        reopened
            .compatibility
            .upsert(&variant_key, updated.clone(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        reopened
            .enforce_compatibility_integrity()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let revisions = reopened
            .list_compatibility_revisions_for_variant(&variant_key)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(revisions.len(), 2);
        assert_eq!(
            revisions.iter().map(|row| row.revision).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            revisions
                .iter()
                .map(|row| row.report.notes.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Legacy direct-kernel software variant",
                "Updated direct-kernel software variant",
            ]
        );
        assert_eq!(
            revisions
                .iter()
                .map(|row| row.active_version)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    #[tokio::test]
    async fn region_cell_policy_defaults_and_normalizes_variant_overrides() {
        let (_temp, service, context) = test_service().await;

        let created = service
            .create_region_cell_policy(
                CreateRegionCellPolicyRequest {
                    name: String::from("EU Sovereign Cell"),
                    region: String::from("EU-WEST"),
                    cell: Some(String::from("CELL-A")),
                    policy_mode: String::from("SOVEREIGN"),
                    require_local_artifacts: None,
                    fallback_regions: Some(vec![
                        String::from("eu-west"),
                        String::from("eu-west"),
                        String::from("eu-central"),
                    ]),
                    fallback_cells: Some(vec![
                        String::from("cell-b"),
                        String::from("cell-b"),
                        String::from("cell-c"),
                    ]),
                    notes: String::from("Keep sovereign-capable artifacts pinned to local stock."),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let record: UvmRegionCellPolicyRecord = response_json(created).await;
        assert_eq!(record.region, "eu-west");
        assert_eq!(record.cell.as_deref(), Some("cell-a"));
        assert_eq!(record.policy_mode, "sovereign");
        assert!(record.require_local_artifacts);
        assert_eq!(
            record.fallback_regions,
            vec![String::from("eu-central"), String::from("eu-west")]
        );
        assert_eq!(
            record.fallback_cells,
            vec![String::from("cell-b"), String::from("cell-c")]
        );
    }

    #[tokio::test]
    async fn sovereign_region_cell_policy_cannot_disable_local_artifact_requirement() {
        let (_temp, service, context) = test_service().await;

        let error = service
            .create_region_cell_policy(
                CreateRegionCellPolicyRequest {
                    name: String::from("invalid-sovereign"),
                    region: String::from("eu-west"),
                    cell: None,
                    policy_mode: String::from("sovereign"),
                    require_local_artifacts: Some(false),
                    fallback_regions: None,
                    fallback_cells: None,
                    notes: String::from("This should be rejected."),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected sovereign local-artifact rejection"));

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert_eq!(
            error.message,
            "sovereign region/cell policies must require local artifacts"
        );
    }

    #[tokio::test]
    async fn images_summary_reflects_persisted_state() {
        let (_temp, service, context) = test_service().await;

        let bundle_response = service
            .create_firmware_bundle(
                CreateFirmwareBundleRequest {
                    name: String::from("bundle-a"),
                    architecture: String::from("x86_64"),
                    firmware_profile: String::from("uefi_standard"),
                    artifact_uri: String::from("file:///firmware/a.bin"),
                    secure_boot_capable: Some(true),
                    verified: Some(true),
                    secure_boot_posture: None,
                    signer_lineage: Vec::new(),
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_bundle: UvmFirmwareBundleRecord = response_json(bundle_response).await;

        let bundle_response = service
            .create_firmware_bundle(
                CreateFirmwareBundleRequest {
                    name: String::from("bundle-b"),
                    architecture: String::from("x86_64"),
                    firmware_profile: String::from("bios"),
                    artifact_uri: String::from("file:///firmware/b.bin"),
                    secure_boot_capable: Some(false),
                    verified: Some(false),
                    secure_boot_posture: None,
                    signer_lineage: Vec::new(),
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _second_bundle: UvmFirmwareBundleRecord = response_json(bundle_response).await;

        let guest_profile_response = service
            .create_guest_profile(
                CreateGuestProfileRequest {
                    name: String::from("linux-standard"),
                    guest_profile: String::from("linux_standard"),
                    architecture: String::from("x86_64"),
                    machine_family: String::from("general_purpose_pci"),
                    boot_path: String::from("microvm"),
                    firmware_bundle_id: Some(first_bundle.id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let guest_profile: UvmGuestProfileRecord = response_json(guest_profile_response).await;

        let overlay_response = service
            .create_overlay_policy(
                CreateOverlayPolicyRequest {
                    name: String::from("base-policy"),
                    root_mode: String::from("read_only_base"),
                    writable_layer_limit: Some(2),
                    template_clone_enabled: Some(true),
                    chain_compatibility: None,
                    publication: None,
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let overlay_policy: UvmOverlayPolicyRecord = response_json(overlay_response).await;

        let region_cell_policy_response = service
            .create_region_cell_policy(
                CreateRegionCellPolicyRequest {
                    name: String::from("regional-degraded-fallback"),
                    region: String::from("us-east"),
                    cell: Some(String::from("us-east:cell-a")),
                    policy_mode: String::from("degraded"),
                    require_local_artifacts: Some(false),
                    fallback_regions: Some(vec![String::from("us-central")]),
                    fallback_cells: Some(vec![String::from("us-east:cell-b")]),
                    notes: String::from("Allow bounded degraded spillover during cell outages."),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let _region_cell_policy: UvmRegionCellPolicyRecord =
            response_json(region_cell_policy_response).await;

        let first_digest = "d".repeat(64);
        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/base.raw"),
                    guest_os: String::from("linux-24"),
                    architecture: String::from("x86_64"),
                    digest: Some(first_digest.clone()),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: Some(guest_profile.id.to_string()),
                    overlay_policy_id: Some(overlay_policy.id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let first_image: UvmImageRecord = response_json(created).await;

        service
            .verify_image(
                first_image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some(first_image.digest.clone()),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let second_digest = "e".repeat(64);
        service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("iso"),
                    source_uri: String::from("file:///images/media.iso"),
                    guest_os: String::from("ubuntu-26.04"),
                    architecture: String::from("x86_64"),
                    digest: Some(second_digest),
                    signature_attestation: None,
                    provenance_attestation: None,
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let summary = service
            .image_summary()
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(summary.total_images, 2);
        assert_eq!(summary.verified_images, 1);
        assert_eq!(summary.unverified_images, 1);
        assert_eq!(summary.signature_verified_images, 1);
        assert_eq!(summary.provenance_verified_images, 1);
        assert_eq!(summary.artifact_verified_images, 1);
        assert_eq!(summary.total_firmware_bundles, 2);
        assert_eq!(summary.verified_firmware_bundles, 1);
        assert_eq!(summary.total_guest_profiles, 1);
        assert_eq!(summary.total_overlay_policies, 1);
        assert_eq!(summary.total_region_cell_policies, 1);
        assert_eq!(summary.architecture_counts.get("x86_64"), Some(&2));
        assert_eq!(summary.source_kind_counts.get("raw"), Some(&1));
        assert_eq!(summary.source_kind_counts.get("iso"), Some(&1));
    }

    #[tokio::test]
    async fn deleted_images_are_rejected_by_verify_and_promote() {
        let (_temp, service, context) = test_service().await;
        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("s3://artifacts/deleted.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("4".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        let stored = service
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing image"));
        service
            .images
            .soft_delete(image.id.as_str(), Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let verify_error = service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("4".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected deleted image verify rejection"));
        assert_eq!(verify_error.code, uhost_core::ErrorCode::NotFound);

        let promote_error = service
            .promote_image(image.id.as_str(), promote_request("stable"), &context)
            .await
            .err()
            .unwrap_or_else(|| panic!("expected deleted image promote rejection"));
        assert_eq!(promote_error.code, uhost_core::ErrorCode::NotFound);
    }

    #[tokio::test]
    async fn firmware_profiles_and_overlay_policies_bind_to_imported_images() {
        let (_temp, service, context) = test_service().await;

        let firmware = service
            .create_firmware_bundle(
                CreateFirmwareBundleRequest {
                    name: String::from("linux-uefi"),
                    architecture: String::from("x86_64"),
                    firmware_profile: String::from("uefi_standard"),
                    artifact_uri: String::from("object://firmware/linux-uefi.fd"),
                    secure_boot_capable: Some(false),
                    verified: Some(true),
                    secure_boot_posture: None,
                    signer_lineage: Vec::new(),
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let firmware_record: UvmFirmwareBundleRecord = response_json(firmware).await;

        let profile = service
            .create_guest_profile(
                CreateGuestProfileRequest {
                    name: String::from("linux-standard"),
                    guest_profile: String::from("linux_standard"),
                    architecture: String::from("x86_64"),
                    machine_family: String::from("general_purpose_pci"),
                    boot_path: String::from("general_purpose"),
                    firmware_bundle_id: Some(firmware_record.id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let profile_record: UvmGuestProfileRecord = response_json(profile).await;

        let overlay = service
            .create_overlay_policy(
                CreateOverlayPolicyRequest {
                    name: String::from("writable-cow"),
                    root_mode: String::from("writable_cow"),
                    writable_layer_limit: Some(2),
                    template_clone_enabled: Some(true),
                    chain_compatibility: None,
                    publication: None,
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let overlay_record: UvmOverlayPolicyRecord = response_json(overlay).await;

        let imported = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("object://images/linux-base.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("5".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: Some(profile_record.id.to_string()),
                    overlay_policy_id: Some(overlay_record.id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let imported_record: UvmImageRecord = response_json(imported).await;
        assert_eq!(imported_record.guest_profile, "linux_standard");
        assert_eq!(imported_record.machine_family, "general_purpose_pci");
        assert_eq!(
            imported_record.guest_profile_id.as_ref(),
            Some(&profile_record.id)
        );
        assert_eq!(
            imported_record.overlay_policy_id.as_ref(),
            Some(&overlay_record.id)
        );

        let firmware_rows = service
            .list_firmware_bundles()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let profile_rows = service
            .list_guest_profiles()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let overlay_rows = service
            .list_overlay_policies()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(firmware_rows.len(), 1);
        assert_eq!(profile_rows.len(), 1);
        assert_eq!(overlay_rows.len(), 1);
    }

    #[tokio::test]
    async fn overlay_policy_defaults_expand_to_explicit_chain_and_publication_rules() {
        let (_temp, service, context) = test_service().await;

        let overlay = service
            .create_overlay_policy(
                CreateOverlayPolicyRequest {
                    name: String::from("default-overlay"),
                    root_mode: String::from("read_only_base"),
                    writable_layer_limit: None,
                    template_clone_enabled: None,
                    chain_compatibility: None,
                    publication: None,
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let overlay_record: UvmOverlayPolicyRecord = response_json(overlay).await;

        assert_eq!(
            overlay_record.chain_compatibility.base_source_kinds,
            vec!["iso", "qcow2", "raw", "vhdx"]
        );
        assert_eq!(
            overlay_record.chain_compatibility.machine_families,
            vec!["aarch64_virt", "general_purpose_pci", "microvm_linux"]
        );
        assert_eq!(
            overlay_record.chain_compatibility.guest_profiles,
            vec![
                "apple_guest",
                "bsd_general",
                "linux_direct_kernel",
                "linux_standard",
                "windows_general",
            ]
        );
        assert_eq!(
            overlay_record.publication.allowed_channels,
            vec!["canary", "preview", "stable"]
        );
        assert!(overlay_record.publication.allowed_host_classes.is_empty());
        assert!(overlay_record.publication.allowed_regions.is_empty());
        assert!(overlay_record.publication.allowed_cells.is_empty());
    }

    #[tokio::test]
    async fn overlay_policy_persists_attestation_records() {
        let (_temp, service, context) = test_service().await;

        let overlay = service
            .create_overlay_policy(
                CreateOverlayPolicyRequest {
                    name: String::from("attested-overlay"),
                    root_mode: String::from("read_only_base"),
                    writable_layer_limit: Some(2),
                    template_clone_enabled: Some(true),
                    chain_compatibility: None,
                    publication: None,
                    signature_attestation: Some(String::from("sigstore://overlay/base")),
                    provenance_attestation: Some(String::from("provstore://overlay/base")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let overlay_record: UvmOverlayPolicyRecord = response_json(overlay).await;

        assert!(super::artifact_has_attestation_kind(
            &overlay_record.attestations,
            UvmArtifactAttestationKind::Signature
        ));
        assert!(super::artifact_has_attestation_kind(
            &overlay_record.attestations,
            UvmArtifactAttestationKind::Provenance
        ));
        assert_eq!(overlay_record.attestations.len(), 2);
    }

    #[tokio::test]
    async fn overlay_policy_chain_rules_reject_incompatible_image_imports() {
        let (_temp, service, context) = test_service().await;

        let overlay = service
            .create_overlay_policy(
                CreateOverlayPolicyRequest {
                    name: String::from("microvm-only"),
                    root_mode: String::from("writable_cow"),
                    writable_layer_limit: Some(2),
                    template_clone_enabled: Some(true),
                    chain_compatibility: Some(UvmOverlayChainCompatibilityRules {
                        base_source_kinds: vec![String::from("raw")],
                        machine_families: vec![String::from("microvm_linux")],
                        guest_profiles: vec![String::from("linux_standard")],
                    }),
                    publication: None,
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let overlay_record: UvmOverlayPolicyRecord = response_json(overlay).await;

        let error = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/linux.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("6".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: Some(overlay_record.id.to_string()),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected overlay compatibility rejection"));
        assert_eq!(error.code, uhost_core::ErrorCode::Conflict);
    }

    #[tokio::test]
    async fn overlay_policy_publication_rules_gate_promotions() {
        let (_temp, service, context) = test_service().await;

        let overlay = service
            .create_overlay_policy(
                CreateOverlayPolicyRequest {
                    name: String::from("regional-canary"),
                    root_mode: String::from("writable_cow"),
                    writable_layer_limit: Some(2),
                    template_clone_enabled: Some(true),
                    chain_compatibility: Some(UvmOverlayChainCompatibilityRules {
                        base_source_kinds: vec![String::from("raw"), String::from("raw")],
                        machine_families: vec![String::from("general_purpose_pci")],
                        guest_profiles: vec![String::from("linux_standard")],
                    }),
                    publication: Some(UvmOverlayPublicationRules {
                        allowed_channels: vec![String::from("canary"), String::from("canary")],
                        allowed_host_classes: vec![String::from("edge")],
                        allowed_regions: vec![String::from("us-east-1")],
                        allowed_cells: vec![String::from("cell-a")],
                    }),
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let overlay_record: UvmOverlayPolicyRecord = response_json(overlay).await;
        assert_eq!(overlay_record.publication.allowed_channels, vec!["canary"]);

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/canary.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("7".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: Some(overlay_record.id.to_string()),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image_record: UvmImageRecord = response_json(created).await;
        assert!(image_record.compatibility_evidence.iter().any(|row| {
            row.summary.contains("overlay_policy=")
                && row.summary.contains("publication_channels=")
                && row.summary.contains("host_classes=edge")
                && row.summary.contains("regions=us-east-1")
                && row.summary.contains("cells=cell-a")
        }));

        service
            .verify_image(
                image_record.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some(image_record.digest.clone()),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let regional_edge_row = scoped_compatibility_row(
            "edge",
            "us-east-1",
            "cell-a",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Regional edge publication path for overlay-backed canary releases",
        );
        let regional_edge_key = super::compatibility_variant_key(&regional_edge_row);
        service
            .compatibility
            .create(&regional_edge_key, regional_edge_row)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let wrong_channel_error = service
            .promote_image(
                image_record.id.as_str(),
                PromoteImageRequest {
                    channel: String::from("stable"),
                    host_class: Some(String::from("edge")),
                    machine_family: None,
                    guest_profile: None,
                    region: Some(String::from("us-east-1")),
                    cell: Some(String::from("cell-a")),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected overlay publication channel rejection"));
        assert_eq!(wrong_channel_error.code, uhost_core::ErrorCode::Conflict);

        let wrong_scope_error = service
            .promote_image(
                image_record.id.as_str(),
                PromoteImageRequest {
                    channel: String::from("canary"),
                    host_class: Some(String::from("core")),
                    machine_family: None,
                    guest_profile: None,
                    region: Some(String::from("us-east-1")),
                    cell: Some(String::from("cell-a")),
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected overlay publication scope rejection"));
        assert_eq!(wrong_scope_error.code, uhost_core::ErrorCode::Conflict);

        let promoted = service
            .promote_image(
                image_record.id.as_str(),
                PromoteImageRequest {
                    channel: String::from("canary"),
                    host_class: Some(String::from("edge")),
                    machine_family: None,
                    guest_profile: None,
                    region: Some(String::from("us-east-1")),
                    cell: Some(String::from("cell-a")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let promoted_record: UvmImageRecord = response_json(promoted).await;
        assert_eq!(promoted_record.promoted_channel.as_deref(), Some("canary"));
        assert_eq!(promoted_record.publication_manifests.len(), 1);
    }

    #[tokio::test]
    async fn firmware_bundle_policy_derives_secure_boot_lineage_artifact() {
        let (_temp, service, context) = test_service().await;

        let created = service
            .create_firmware_bundle(
                CreateFirmwareBundleRequest {
                    name: String::from("secure-fw"),
                    architecture: String::from("x86_64"),
                    firmware_profile: String::from("uefi_secure"),
                    artifact_uri: String::from("file:///firmware/secure.fd"),
                    secure_boot_capable: Some(true),
                    verified: Some(true),
                    secure_boot_posture: None,
                    signer_lineage: vec![
                        CreateFirmwareSignerLineageEntryRequest {
                            role: String::from("PLATFORM_ROOT"),
                            signer: String::from("Platform Root CA"),
                            issuer: None,
                        },
                        CreateFirmwareSignerLineageEntryRequest {
                            role: String::from("bundle_signer"),
                            signer: String::from("Firmware Bundle Signer"),
                            issuer: Some(String::from("Platform Root CA")),
                        },
                    ],
                    signature_attestation: Some(String::from("sigstore://firmware/secure")),
                    provenance_attestation: Some(String::from("provstore://firmware/secure")),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let record: UvmFirmwareBundleRecord = response_json(created).await;

        assert_eq!(record.secure_boot_posture, "required");
        assert_eq!(record.policy_revision, 1);
        assert_eq!(record.signer_lineage.len(), 2);
        assert_eq!(record.signer_lineage[0].role, "platform_root");
        assert_eq!(
            record.signer_lineage[1].issuer.as_deref(),
            Some("Platform Root CA")
        );
        assert_eq!(record.attestations.len(), 2);
    }

    #[tokio::test]
    async fn firmware_bundle_policy_rejects_incompatible_secure_boot_posture() {
        let (_temp, service, context) = test_service().await;

        let error = service
            .create_firmware_bundle(
                CreateFirmwareBundleRequest {
                    name: String::from("bios-fw"),
                    architecture: String::from("x86_64"),
                    firmware_profile: String::from("bios"),
                    artifact_uri: String::from("file:///firmware/bios.fd"),
                    secure_boot_capable: Some(false),
                    verified: Some(true),
                    secure_boot_posture: Some(String::from("optional")),
                    signer_lineage: Vec::new(),
                    signature_attestation: None,
                    provenance_attestation: None,
                },
                &context,
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("expected secure boot posture rejection"));

        assert_eq!(error.code, uhost_core::ErrorCode::InvalidInput);
        assert!(
            error.message.contains("bios"),
            "unexpected error message: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn reopen_backfills_legacy_promoted_channel_into_audit_linked_publication_manifests() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/legacy.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("8".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("8".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored image"));
        let mut legacy = stored.value.clone();
        legacy.promoted_channel = Some(String::from("stable"));
        legacy.publication_manifests.clear();
        legacy
            .metadata
            .touch(String::from("legacy-promoted-channel"));
        service
            .images
            .upsert(image.id.as_str(), legacy, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migrated = reopened
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migrated image"));

        assert_eq!(migrated.value.promoted_channel.as_deref(), Some("stable"));
        assert!(!migrated.value.publication_manifests.is_empty());
        assert!(
            migrated
                .value
                .publication_manifests
                .iter()
                .all(|manifest| manifest.channel == "stable"
                    && !manifest.audit_event_id.as_str().is_empty())
        );
        assert!(
            migrated
                .value
                .publication_manifests
                .iter()
                .any(|manifest| manifest.compatibility_row_id.is_some())
        );

        let outbox = reopened
            .list_outbox_messages()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            outbox
                .iter()
                .any(|message| message.topic == "uvm.image.publication_manifests.backfilled.v1")
        );
    }

    #[tokio::test]
    async fn reopen_expands_legacy_promoted_channel_across_matching_publication_tuples() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/tuple-expansion.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("9".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("9".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let east_row = scoped_compatibility_row(
            "legacy_host_east",
            "us-east1",
            "us-east1:cell-a",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Legacy east publication tuple",
        );
        let west_row = scoped_compatibility_row(
            "legacy_host_west",
            "us-west1",
            "us-west1:cell-b",
            "general_purpose_pci",
            "linux_standard",
            "compatible",
            "Legacy west publication tuple",
        );
        service
            .compatibility
            .create(&super::compatibility_variant_key(&east_row), east_row)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        service
            .compatibility
            .create(&super::compatibility_variant_key(&west_row), west_row)
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored image"));
        let mut legacy = stored.value.clone();
        legacy.promoted_channel = Some(String::from("stable"));
        legacy.publication_manifests.clear();
        legacy
            .metadata
            .touch(String::from("legacy-promoted-channel-expansion"));
        service
            .images
            .upsert(image.id.as_str(), legacy, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migrated = reopened
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migrated image"));

        assert!(migrated.value.publication_manifests.iter().any(|manifest| {
            manifest.channel == "stable"
                && manifest.host_class == "legacy_host_east"
                && manifest.region == "us-east1"
                && manifest.cell == "us-east1:cell-a"
        }));
        assert!(migrated.value.publication_manifests.iter().any(|manifest| {
            manifest.channel == "stable"
                && manifest.host_class == "legacy_host_west"
                && manifest.region == "us-west1"
                && manifest.cell == "us-west1:cell-b"
        }));
    }

    #[tokio::test]
    async fn reopen_uses_default_scope_fallback_when_legacy_promotion_has_no_exact_row() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let service = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let context = RequestContext::new().unwrap_or_else(|error| panic!("{error}"));

        let created = service
            .import_image(
                ImportImageRequest {
                    source_kind: String::from("raw"),
                    source_uri: String::from("file:///images/fallback.raw"),
                    guest_os: String::from("linux"),
                    architecture: String::from("x86_64"),
                    digest: Some("a".repeat(64)),
                    signature_attestation: Some(String::from("sig")),
                    provenance_attestation: Some(String::from("prov")),
                    license_token: None,
                    guest_profile_id: None,
                    overlay_policy_id: None,
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let image: UvmImageRecord = response_json(created).await;
        service
            .verify_image(
                image.id.as_str(),
                VerifyImageRequest {
                    expected_digest: Some("a".repeat(64)),
                    require_signature: Some(true),
                    require_provenance: Some(true),
                },
                &context,
            )
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let stored = service
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing stored image"));
        let mut legacy = stored.value.clone();
        legacy.machine_family = String::from("legacy_unknown_family");
        legacy.promoted_channel = Some(String::from("preview"));
        legacy.publication_manifests.clear();
        legacy
            .metadata
            .touch(String::from("legacy-promoted-channel-fallback"));
        service
            .images
            .upsert(image.id.as_str(), legacy, Some(stored.version))
            .await
            .unwrap_or_else(|error| panic!("{error}"));

        let reopened = UvmImageService::open(temp.path())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let migrated = reopened
            .images
            .get(image.id.as_str())
            .await
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(|| panic!("missing migrated image"));
        let fallback_manifest = migrated
            .value
            .publication_manifests
            .iter()
            .find(|manifest| {
                manifest.channel == "preview"
                    && manifest.host_class == "default"
                    && manifest.machine_family == "legacy_unknown_family"
                    && manifest.region == "global"
                    && manifest.cell == "global"
            })
            .unwrap_or_else(|| panic!("missing fallback legacy publication manifest"));

        assert!(fallback_manifest.compatibility_row_id.is_none());
        assert!(!fallback_manifest.policy_approved);
        assert_eq!(fallback_manifest.claim_tier, migrated.value.claim_tier);
    }

    #[test]
    fn publication_manifest_state_fingerprint_tracks_audit_linked_state() {
        let original = vec![publication_manifest(
            "stable",
            "linux-software_dbt-x86_64",
            "global",
            "global",
            Some("ucr_original"),
            "original-match",
            "aud_original",
            10,
        )];
        let updated = vec![publication_manifest(
            "stable",
            "linux-software_dbt-x86_64",
            "global",
            "global",
            Some("ucr_updated"),
            "updated-match",
            "aud_updated",
            20,
        )];

        assert_ne!(
            super::publication_manifest_state_fingerprint("uim_publicationstate", &original),
            super::publication_manifest_state_fingerprint("uim_publicationstate", &updated)
        );
    }
}
