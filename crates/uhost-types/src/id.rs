//! Strongly typed identifiers used across service boundaries.
//!
//! UHost uses prefixed, URL-safe identifiers so logs and audit events remain
//! readable by operators while still being stable enough for machine use.
//! Prefixes make it obvious which subsystem produced an identifier and reduce
//! the chance that unrelated IDs are confused during manual operations.

use core::fmt;
use core::str::FromStr;

use getrandom::fill as fill_random;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const ID_BODY_TIMESTAMP_BYTES: usize = 8;
const ID_BODY_RANDOM_BYTES: usize = 10;
const ID_BODY_TOTAL_BYTES: usize = ID_BODY_TIMESTAMP_BYTES + ID_BODY_RANDOM_BYTES;

/// Failure modes for ID parsing and generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// The string does not start with the expected prefix.
    InvalidPrefix {
        /// The expected prefix without separator.
        expected: &'static str,
        /// The actual input string.
        actual: String,
    },
    /// The string shape does not match the `<prefix>_<body>` invariant.
    InvalidShape(String),
    /// The body contains characters outside the supported lowercase alphabet.
    InvalidCharacter(char),
    /// The operating system did not provide cryptographically secure entropy.
    RandomnessUnavailable(String),
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix { expected, actual } => {
                write!(formatter, "expected id prefix `{expected}`, got `{actual}`")
            }
            Self::InvalidShape(value) => {
                write!(formatter, "invalid identifier shape `{value}`")
            }
            Self::InvalidCharacter(character) => {
                write!(formatter, "invalid identifier character `{character}`")
            }
            Self::RandomnessUnavailable(message) => {
                write!(formatter, "randomness unavailable: {message}")
            }
        }
    }
}

impl std::error::Error for IdError {}

fn parse_id(value: String, expected_prefix: &'static str) -> Result<String, IdError> {
    let Some((prefix, body)) = value.split_once('_') else {
        return Err(IdError::InvalidShape(value));
    };

    if prefix != expected_prefix {
        return Err(IdError::InvalidPrefix {
            expected: expected_prefix,
            actual: value,
        });
    }

    validate_body(body)?;
    Ok(format!("{prefix}_{body}"))
}

fn encode_base32(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut buffer = 0_u16;
    let mut bits = 0_u8;

    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;

        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            output.push(BASE32_ALPHABET[index] as char);
            bits -= 5;
        }
    }

    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        output.push(BASE32_ALPHABET[index] as char);
    }

    output
}

fn generate_body() -> Result<String, IdError> {
    // The generated body shape is stable across all IDs: 8 bytes of timestamp
    // entropy followed by 10 bytes of random entropy, then lowercase base32.
    let mut random = [0_u8; ID_BODY_RANDOM_BYTES];
    fill_random(&mut random).map_err(|error| IdError::RandomnessUnavailable(error.to_string()))?;

    let timestamp = OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .to_le_bytes();
    let mut combined = [0_u8; ID_BODY_TOTAL_BYTES];
    combined[..ID_BODY_TIMESTAMP_BYTES].copy_from_slice(&timestamp[..ID_BODY_TIMESTAMP_BYTES]);
    combined[ID_BODY_TIMESTAMP_BYTES..].copy_from_slice(&random);

    Ok(encode_base32(&combined))
}

fn validate_body(body: &str) -> Result<(), IdError> {
    if body.is_empty() {
        return Err(IdError::InvalidShape(body.to_owned()));
    }

    for character in body.chars() {
        if !character.is_ascii_lowercase()
            && !matches!(character, '2' | '3' | '4' | '5' | '6' | '7')
        {
            return Err(IdError::InvalidCharacter(character));
        }
    }

    Ok(())
}

macro_rules! define_id {
    ($name:ident, $prefix:literal) => {
        #[doc = "Typed identifier generated and validated for the `"]
        #[doc = $prefix]
        #[doc = "` domain."]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The stable prefix used by this identifier type.
            pub const PREFIX: &'static str = $prefix;

            /// Generate a new identifier using OS entropy and a timestamp shard.
            pub fn generate() -> Result<Self, IdError> {
                let body = generate_body()?;
                Ok(Self(format!("{}_{}", Self::PREFIX, body)))
            }

            /// Parse and validate an existing identifier.
            pub fn parse(value: impl Into<String>) -> Result<Self, IdError> {
                Self::try_from(value.into())
            }

            /// Borrow the underlying string value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = IdError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                parse_id(value, Self::PREFIX).map(Self)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = IdError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from(value.to_owned())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value)
            }
        }
    };
}

define_id!(UserId, "usr");
define_id!(OrganizationId, "org");
define_id!(ProjectId, "prj");
define_id!(EnvironmentId, "env");
define_id!(TenantId, "tnt");
define_id!(SessionId, "ses");
define_id!(ApiKeyId, "key");
define_id!(WorkloadIdentityId, "wli");
define_id!(InvitationId, "inv");
define_id!(ApprovalId, "apr");
define_id!(NodeId, "nod");
define_id!(WorkloadId, "wrk");
define_id!(DeploymentId, "dep");
define_id!(ShardPlacementId, "shp");
define_id!(BucketId, "bkt");
define_id!(VolumeId, "vol");
define_id!(StorageClassId, "stc");
define_id!(DurabilityTierId, "dur");
define_id!(FileShareId, "fsh");
define_id!(ArchiveId, "arc");
define_id!(UploadId, "upl");
define_id!(RehydrateJobId, "rhj");
define_id!(SecretId, "sec");
define_id!(DatabaseId, "dbs");
define_id!(CacheClusterId, "cac");
define_id!(QueueId, "que");
define_id!(StreamConsumerGroupId, "scg");
define_id!(StreamConsumerMemberId, "scm");
define_id!(StreamCheckpointId, "sck");
define_id!(InvoiceId, "invc");
define_id!(BillingAccountId, "bill");
define_id!(SubscriptionId, "sub");
define_id!(NotificationId, "ntf");
define_id!(NotificationTemplateId, "ntm");
define_id!(NotificationPreferenceId, "npr");
define_id!(WebhookEndpointId, "whk");
define_id!(AbuseSignalId, "abs");
define_id!(AbuseCaseId, "abc");
define_id!(AbuseQuarantineId, "abq");
define_id!(AbuseAppealId, "aba");
define_id!(PolicyId, "pol");
define_id!(NetPolicyId, "npl");
define_id!(AlertRuleId, "alr");
define_id!(AuditId, "aud");
define_id!(FlowAuditId, "fla");
define_id!(MailDomainId, "mld");
define_id!(MailRouteId, "mlr");
define_id!(IpSetId, "ips");
define_id!(PrivateNetworkId, "pnt");
define_id!(SubnetId, "snt");
define_id!(RouteTableId, "rtb");
define_id!(PrivateRouteId, "prt");
define_id!(NextHopId, "nhp");
define_id!(NatGatewayId, "nat");
define_id!(TransitAttachmentId, "trn");
define_id!(VpnConnectionId, "vpn");
define_id!(PeeringConnectionId, "peer");
define_id!(ServiceIdentityId, "sid");
define_id!(ServiceConnectAttachmentId, "sca");
define_id!(EdgePublicationTargetId, "ept");
define_id!(EgressRuleId, "egr");
define_id!(LegalHoldId, "lgh");
define_id!(RetentionPolicyId, "rtn");
define_id!(ChangeRequestId, "chg");
define_id!(AuditCheckpointId, "acp");
define_id!(LeaderLeaseId, "lls");
define_id!(ReplicationStreamId, "rpl");
define_id!(FailoverOperationId, "fov");
define_id!(MigrationJobId, "mjr");
define_id!(RolloutPlanId, "rol");
define_id!(RepairJobId, "rpj");
define_id!(DeadLetterId, "dlq");
define_id!(PluginId, "plg");
define_id!(ZoneId, "dns");
define_id!(DnsPublicationIntentId, "dpi");
define_id!(RouteId, "rte");
define_id!(UvmInstanceId, "uvi");
define_id!(UvmImageId, "uim");
define_id!(UvmSnapshotId, "uvs");
define_id!(UvmMigrationId, "uvm");
define_id!(UvmTemplateId, "uvt");
define_id!(UvmNodeCapabilityId, "unc");
define_id!(UvmNodeDrainId, "und");
define_id!(UvmDeviceProfileId, "udp");
define_id!(UvmPerfAttestationId, "upa");
define_id!(UvmFailureReportId, "ufr");
define_id!(UvmCompatibilityReportId, "ucr");
define_id!(UvmRuntimeSessionId, "urs");
define_id!(UvmCheckpointId, "uck");
define_id!(UvmFirmwareBundleId, "ufb");
define_id!(UvmGuestProfileId, "ugp");
define_id!(UvmOverlayPolicyId, "uop");
define_id!(UvmRegionCellPolicyId, "urp");
define_id!(UvmHostEvidenceId, "uhe");
define_id!(UvmClaimDecisionId, "ucd");
define_id!(UvmBenchmarkCampaignId, "ubc");
define_id!(UvmBenchmarkBaselineId, "ubb");
define_id!(UvmBenchmarkResultId, "ubr");

#[cfg(test)]
mod tests {
    use super::{
        IdError, StreamCheckpointId, StreamConsumerGroupId, StreamConsumerMemberId, SubscriptionId,
        UserId,
    };

    #[test]
    fn generated_ids_keep_expected_prefix() {
        let identifier = UserId::generate().unwrap_or_else(|error| panic!("{error}"));
        assert!(identifier.as_str().starts_with("usr_"));
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        let error = UserId::parse("org_deadbeef".to_owned())
            .err()
            .unwrap_or_else(|| panic!("expected invalid prefix"));

        assert!(matches!(error, IdError::InvalidPrefix { .. }));
    }

    #[test]
    fn serde_round_trips_valid_ids() {
        let identifier = UserId::parse("usr_abcdefghijklmnopqrstu".to_owned())
            .unwrap_or_else(|error| panic!("{error}"));

        let encoded = serde_json::to_string(&identifier).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(encoded, "\"usr_abcdefghijklmnopqrstu\"");

        let decoded: UserId =
            serde_json::from_str(&encoded).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(decoded, identifier);
    }

    #[test]
    fn serde_rejects_invalid_ids() {
        let decoded = serde_json::from_str::<UserId>("\"org_deadbeef\"");
        assert!(decoded.is_err());
    }

    #[test]
    fn stream_consumer_ids_keep_dedicated_prefixes() {
        let consumer_group =
            StreamConsumerGroupId::generate().unwrap_or_else(|error| panic!("{error}"));
        let consumer_member =
            StreamConsumerMemberId::generate().unwrap_or_else(|error| panic!("{error}"));
        let checkpoint = StreamCheckpointId::generate().unwrap_or_else(|error| panic!("{error}"));

        assert!(consumer_group.as_str().starts_with("scg_"));
        assert!(consumer_member.as_str().starts_with("scm_"));
        assert!(checkpoint.as_str().starts_with("sck_"));

        assert!(SubscriptionId::parse(consumer_group.to_string()).is_err());
        assert!(SubscriptionId::parse(consumer_member.to_string()).is_err());
        assert!(SubscriptionId::parse(checkpoint.to_string()).is_err());
    }
}
