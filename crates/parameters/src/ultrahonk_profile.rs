//! Bounded wire codecs for ZKA UltraHonk v1 circuit profiles.
//!
//! This module implements the fixed-layout profile records specified by ZKA
//! ADR-0009. It is deliberately non-activating: it does not define a canonical
//! production profile identifier, discriminator, allowlist, CRS, gas schedule,
//! resource schedule, storage key, or governance/activation API. A protocol
//! release must still select and independently review all artifacts named by a
//! profile before any decoded value can become consensus-active.
//!
//! The codecs are written manually so hostile length prefixes are rejected
//! before allocation and every decoder requires full-buffer consumption.

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Schema version shared by the v1 profile wire records.
pub const CIRCUIT_PROFILE_SCHEMA_VERSION_V1: u32 = 1;

/// Number of circuit rows in a v1 profile allowlist.
pub const CIRCUIT_PROFILE_ENTRY_COUNT_V1: u32 = 3;

/// Encoded byte length of [`CircuitProfileBindingV1`].
pub const CIRCUIT_PROFILE_BINDING_V1_ENCODED_LEN: usize = 615;

/// Encoded byte length of [`CircuitProfileAllowlistV1`].
pub const CIRCUIT_PROFILE_ALLOWLIST_V1_ENCODED_LEN: usize = 1_885;

/// Encoded byte length of [`TrustedSetupProvenanceV1`].
pub const TRUSTED_SETUP_PROVENANCE_V1_ENCODED_LEN: usize = 100;

/// Encoded byte length of an inactive allowlist selection (`None`).
pub const ACTIVE_CIRCUIT_PROFILE_ALLOWLIST_V1_NONE_LEN: usize = 5;

/// Encoded byte length of an active allowlist selection (`Some`).
pub const ACTIVE_CIRCUIT_PROFILE_ALLOWLIST_V1_SOME_LEN: usize = 37;

/// Exact proof-length ceiling fixed by the ADR-0009 v1 host ABI and schema.
///
/// A profile that needs a larger proof must use a separately versioned ABI,
/// schema, codec type, and schema digest.
pub const MAX_PROOF_V1_BYTES: u32 = 7_232;

/// Exact UltraHonk verification-key length supported by the v1 registry shape.
pub const ULTRAHONK_VK_V1_BYTES: u32 = 1_888;

/// Maximum encoded public-input bytes supported by the v1 registry shape.
pub const MAX_PUBLIC_INPUTS_V1_BYTES: u32 = 160;

/// Maximum number of public inputs supported by the v1 registry shape.
pub const MAX_PUBLIC_INPUT_ARITY_V1: u32 = 5;

/// Maximum inline verifier-CRS bytes supported by the v1 registry shape.
pub const MAX_VERIFIER_CRS_V1_BYTES: u32 = 4_096;

/// Import circuit discriminator code.
pub const IMPORT_CIRCUIT_CODE: u8 = 1;

/// Export circuit discriminator code.
pub const EXPORT_CIRCUIT_CODE: u8 = 2;

/// Transfer circuit discriminator code.
pub const TRANSFER_CIRCUIT_CODE: u8 = 3;

/// Import circuit statement domain fixed by ADR-0009.
pub const IMPORT_STATEMENT_DOMAIN: [u8; 32] = [
    0x3c, 0x38, 0x5d, 0x28, 0xbd, 0xfc, 0x49, 0x64, 0xa2, 0x7e, 0xf6, 0x93,
    0xc4, 0xdb, 0xfb, 0x23, 0x73, 0x70, 0x08, 0x14, 0x6b, 0xea, 0xe6, 0x36,
    0x57, 0xac, 0x30, 0xc3, 0x12, 0xe7, 0x2b, 0x70,
];

/// Export circuit statement domain fixed by ADR-0009.
pub const EXPORT_STATEMENT_DOMAIN: [u8; 32] = [
    0x50, 0x1f, 0xca, 0xab, 0xd6, 0xa2, 0x92, 0xd7, 0x57, 0x32, 0x38, 0x3a,
    0x3e, 0xfc, 0xcd, 0xff, 0x2c, 0xc7, 0x5f, 0x8c, 0x25, 0x49, 0xee, 0x68,
    0xf6, 0x34, 0xd3, 0xdc, 0x15, 0x4b, 0x1c, 0xb0,
];

/// Transfer circuit statement domain fixed by ADR-0009.
pub const TRANSFER_STATEMENT_DOMAIN: [u8; 32] = [
    0xa6, 0x82, 0xf8, 0xf6, 0xc2, 0x20, 0x13, 0x85, 0x43, 0x6d, 0xb7, 0x0a,
    0xdc, 0x2d, 0x4c, 0x47, 0x3d, 0xf5, 0xbd, 0x9a, 0xd0, 0xdd, 0x8d, 0x4d,
    0x91, 0xd2, 0x9e, 0x82, 0x43, 0x17, 0x41, 0x5c,
];

/// Domain-separated digest of the normative v1 registry-entry schema.
pub const REGISTRY_ENTRY_SCHEMA_DIGEST_V1: [u8; 32] = [
    0xb8, 0xdc, 0xb0, 0x0e, 0x58, 0x82, 0x57, 0xb8, 0x3d, 0xd9, 0x5d, 0x47,
    0xde, 0x26, 0xa7, 0xbe, 0x34, 0xfd, 0x90, 0x3f, 0xc5, 0xf6, 0x49, 0x83,
    0x4e, 0xb9, 0xe6, 0xb2, 0xdd, 0x60, 0x7a, 0xe1,
];

const ALLOWLIST_DIGEST_DOMAIN: &[u8] =
    b"zka:namada:ultrahonk:circuit-profile-allowlist:v1";
const CEREMONY_IDENTIFIER_DIGEST_DOMAIN: &[u8] =
    b"zka:namada:ultrahonk:ceremony-identifier:v1";
const CEREMONY_TRANSCRIPT_DIGEST_DOMAIN: &[u8] =
    b"zka:namada:ultrahonk:ceremony-transcript:v1";
const PROVENANCE_SOURCE_BUNDLE_DIGEST_DOMAIN: &[u8] =
    b"zka:namada:ultrahonk:provenance-source-bundle:v1";
const TRUSTED_SETUP_PROVENANCE_DIGEST_DOMAIN: &[u8] =
    b"zka:namada:ultrahonk:trusted-setup-provenance:v1";
const VERIFIER_CRS_ENCODING_DIGEST_DOMAIN: &[u8] =
    b"zka:namada:ultrahonk:verifier-crs-encoding:v1";

/// Errors returned by the bounded v1 profile codecs and validators.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ProfileCodecError {
    /// The input ended before the next fixed-size field was complete.
    #[error("profile encoding ended unexpectedly")]
    UnexpectedEnd,
    /// Bytes remained after the expected record was decoded.
    #[error("profile encoding has {remaining} trailing byte(s)")]
    TrailingBytes {
        /// Number of bytes left unread.
        remaining: usize,
    },
    /// An encoder's fixed output buffer did not match its schema.
    #[error("internal profile encoding length mismatch")]
    InternalLengthMismatch,
    /// A schema version was not the exact v1 value.
    #[error("invalid {record} schema version {actual}; expected 1")]
    InvalidSchemaVersion {
        /// Name of the record containing the version.
        record: &'static str,
        /// Version found on the wire.
        actual: u32,
    },
    /// The allowlist vector prefix did not encode exactly three rows.
    #[error("invalid profile allowlist entry count {actual}; expected 3")]
    InvalidEntryCount {
        /// Entry count found on the wire.
        actual: u32,
    },
    /// A field that must be non-zero was all-zero or numerically zero.
    #[error("profile field `{field}` must be non-zero")]
    ZeroField {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// A fixed protocol tag had an unsupported value.
    #[error("invalid `{field}` tag {actual}; expected {expected}")]
    InvalidTag {
        /// Name of the tag field.
        field: &'static str,
        /// Only accepted value.
        expected: u8,
        /// Value found on the wire.
        actual: u8,
    },
    /// A discriminator used a code outside the exact three-circuit set.
    #[error("invalid circuit discriminator code {0}")]
    InvalidCircuitCode(u8),
    /// A row's statement domain did not match its circuit code.
    #[error("statement domain does not match circuit code {circuit_code}")]
    InvalidStatementDomain {
        /// Circuit code whose domain was checked.
        circuit_code: u8,
    },
    /// A discriminator did not start with the allowlist's profile digest.
    #[error("discriminator prefix does not match profile identifier digest")]
    ProfileIdentifierMismatch,
    /// Allowlist rows were not strictly ordered by raw discriminator bytes.
    #[error("profile allowlist rows are not strictly sorted")]
    EntriesNotStrictlySorted,
    /// The allowlist did not contain each required circuit code exactly once.
    #[error(
        "profile allowlist must contain circuit codes 1, 2, and 3 exactly once"
    )]
    InvalidCircuitCodeSet,
    /// A bounded field exceeded its codec safety ceiling.
    #[error("profile field `{field}` is {actual}, above maximum {maximum}")]
    LimitExceeded {
        /// Name of the bounded field.
        field: &'static str,
        /// Maximum accepted value.
        maximum: u32,
        /// Value found on the wire.
        actual: u32,
    },
    /// The VK length was not the exact fixed v1 length.
    #[error("invalid UltraHonk VK length {actual}; expected 1888")]
    InvalidVkLength {
        /// Value found on the wire.
        actual: u32,
    },
    /// Public-input byte length did not equal 32 times its arity.
    #[error(
        "public-input length {actual} does not match 32-byte field arity {arity}"
    )]
    InvalidPublicInputLength {
        /// Declared public-input byte length.
        actual: u32,
        /// Declared public-input arity.
        arity: u32,
    },
    /// The active-allowlist option tag was neither zero nor one.
    #[error("invalid active allowlist option tag {0}")]
    InvalidOptionTag(u8),
    /// A decoded digest did not match independently supplied canonical bytes.
    #[error("digest mismatch for `{field}`")]
    DigestMismatch {
        /// Name of the mismatched digest field.
        field: &'static str,
    },
}

/// Immutable profile binding for one circuit under a v1 profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitProfileBindingV1 {
    /// Raw 32-byte profile identifier digest followed by one circuit code.
    pub discriminator: [u8; 33],
    /// Statement domain fixed for the circuit code.
    pub statement_domain: [u8; 32],
    /// Proof-system tag; must be zero (UltraHonk).
    pub proof_system: u8,
    /// Curve tag; must be zero (BN254).
    pub curve: u8,
    /// Barretenberg target tag; must be zero (`evm`).
    pub barretenberg_target: u8,
    /// Transcript tag; must be zero (Keccak-256).
    pub transcript: u8,
    /// Zero-knowledge flag; must be one.
    pub zero_knowledge: u8,
    /// IPA-accumulation flag; must be zero.
    pub ipa_accumulation: u8,
    /// Exact proof byte length for this circuit.
    pub proof_len: u32,
    /// Exact verification-key byte length for this circuit.
    pub vk_len: u32,
    /// Exact public-input byte length for this circuit.
    pub public_inputs_len: u32,
    /// Number of 32-byte public-input field elements.
    pub public_input_arity: u32,
    /// Base-two circuit subgroup size exponent.
    pub log_n: u32,
    /// Exact inline verifier-CRS byte length.
    pub verifier_crs_len: u32,
    /// Version of the separately selected resource-limit record.
    pub resource_limits_version: u32,
    /// Version of the separately selected gas schedule.
    pub gas_schedule_version: u32,
    /// Digest of canonical ACIR bytes.
    pub acir_digest: [u8; 32],
    /// Digest of the canonical circuit artifact.
    pub artifact_digest: [u8; 32],
    /// Digest of canonical VK bytes.
    pub vk_digest: [u8; 32],
    /// Barretenberg's canonical VK hash.
    pub bb_vk_hash: [u8; 32],
    /// Digest of the canonical public-input schema.
    pub public_input_schema_digest: [u8; 32],
    /// Digest of the canonical verifier-CRS identifier.
    pub verifier_crs_identifier_digest: [u8; 32],
    /// Digest of the canonical verifier-CRS encoding specification.
    pub verifier_crs_encoding_digest: [u8; 32],
    /// SHA-256 digest of the exact inline verifier-CRS bytes.
    pub verifier_crs_digest: [u8; 32],
    /// Digest of the canonical trusted-setup provenance record.
    pub trusted_setup_provenance_digest: [u8; 32],
    /// Digest of the canonical G1/VK generation artifact.
    pub g1_vk_generation_digest: [u8; 32],
    /// Digest of the canonical security-assumptions artifact.
    pub security_assumptions_digest: [u8; 32],
    /// Digest of the canonical host-ABI schema and vectors.
    pub abi_schema_vector_digest: [u8; 32],
    /// Digest of the exact normative registry-entry schema.
    pub registry_entry_schema_digest: [u8; 32],
    /// Digest of the selected resource-limit record.
    pub resource_limits_digest: [u8; 32],
    /// Digest of the selected gas schedule.
    pub gas_schedule_digest: [u8; 32],
    /// Digest of the producer toolchain manifest.
    pub producer_toolchain_digest: [u8; 32],
}

impl CircuitProfileBindingV1 {
    /// Decode and validate one exact 615-byte binding.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ProfileCodecError> {
        let mut reader = Reader::new(bytes);
        let binding = Self::decode_from(&mut reader)?;
        reader.finish()?;
        binding.validate()?;
        Ok(binding)
    }

    /// Validate all self-contained binding invariants.
    //
    // The profile prefix comparison is performed by
    // `validate_for_profile_identifier`; a standalone binding does not carry
    // the allowlist's expected identifier digest.
    pub fn validate(&self) -> Result<(), ProfileCodecError> {
        ensure_nonzero_bytes(
            "discriminator profile prefix",
            &self.discriminator[..32],
        )?;

        validate_tag("proof_system", self.proof_system, 0)?;
        validate_tag("curve", self.curve, 0)?;
        validate_tag("barretenberg_target", self.barretenberg_target, 0)?;
        validate_tag("transcript", self.transcript, 0)?;
        validate_tag("zero_knowledge", self.zero_knowledge, 1)?;
        validate_tag("ipa_accumulation", self.ipa_accumulation, 0)?;

        let circuit_code = self.discriminator[32];
        let expected_domain = statement_domain_for_code(circuit_code)?;
        if self.statement_domain != expected_domain {
            return Err(ProfileCodecError::InvalidStatementDomain {
                circuit_code,
            });
        }

        ensure_nonzero_u32("proof_len", self.proof_len)?;
        ensure_max("proof_len", self.proof_len, MAX_PROOF_V1_BYTES)?;

        ensure_nonzero_u32("vk_len", self.vk_len)?;
        if self.vk_len != ULTRAHONK_VK_V1_BYTES {
            return Err(ProfileCodecError::InvalidVkLength {
                actual: self.vk_len,
            });
        }

        ensure_nonzero_u32("public_inputs_len", self.public_inputs_len)?;
        ensure_max(
            "public_inputs_len",
            self.public_inputs_len,
            MAX_PUBLIC_INPUTS_V1_BYTES,
        )?;
        ensure_nonzero_u32("public_input_arity", self.public_input_arity)?;
        ensure_max(
            "public_input_arity",
            self.public_input_arity,
            MAX_PUBLIC_INPUT_ARITY_V1,
        )?;
        let expected_public_inputs_len = self
            .public_input_arity
            .checked_mul(32)
            .ok_or(ProfileCodecError::LimitExceeded {
                field: "public_input_arity",
                maximum: MAX_PUBLIC_INPUT_ARITY_V1,
                actual: self.public_input_arity,
            })?;
        if self.public_inputs_len != expected_public_inputs_len {
            return Err(ProfileCodecError::InvalidPublicInputLength {
                actual: self.public_inputs_len,
                arity: self.public_input_arity,
            });
        }

        ensure_nonzero_u32("log_n", self.log_n)?;
        ensure_nonzero_u32("verifier_crs_len", self.verifier_crs_len)?;
        ensure_max(
            "verifier_crs_len",
            self.verifier_crs_len,
            MAX_VERIFIER_CRS_V1_BYTES,
        )?;
        ensure_nonzero_u32(
            "resource_limits_version",
            self.resource_limits_version,
        )?;
        ensure_nonzero_u32("gas_schedule_version", self.gas_schedule_version)?;

        for (field, digest) in self.named_digests() {
            ensure_nonzero_bytes(field, digest)?;
        }
        if self.registry_entry_schema_digest != REGISTRY_ENTRY_SCHEMA_DIGEST_V1
        {
            return Err(ProfileCodecError::DigestMismatch {
                field: "registry_entry_schema_digest",
            });
        }
        Ok(())
    }

    /// Validate this binding against an allowlist profile identifier digest.
    pub fn validate_for_profile_identifier(
        &self,
        profile_identifier_digest: &[u8; 32],
    ) -> Result<(), ProfileCodecError> {
        self.validate()?;
        if self.discriminator[..32] != profile_identifier_digest[..] {
            return Err(ProfileCodecError::ProfileIdentifierMismatch);
        }
        Ok(())
    }

    /// Encode one validated binding into its exact 615-byte wire form.
    pub fn to_bytes(
        &self,
    ) -> Result<[u8; CIRCUIT_PROFILE_BINDING_V1_ENCODED_LEN], ProfileCodecError>
    {
        self.validate()?;
        let mut bytes = [0_u8; CIRCUIT_PROFILE_BINDING_V1_ENCODED_LEN];
        let mut writer = Writer::new(&mut bytes);
        self.encode_into(&mut writer)?;
        writer.finish()?;
        Ok(bytes)
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, ProfileCodecError> {
        Ok(Self {
            discriminator: reader.read_array()?,
            statement_domain: reader.read_array()?,
            proof_system: reader.read_u8()?,
            curve: reader.read_u8()?,
            barretenberg_target: reader.read_u8()?,
            transcript: reader.read_u8()?,
            zero_knowledge: reader.read_u8()?,
            ipa_accumulation: reader.read_u8()?,
            proof_len: reader.read_u32()?,
            vk_len: reader.read_u32()?,
            public_inputs_len: reader.read_u32()?,
            public_input_arity: reader.read_u32()?,
            log_n: reader.read_u32()?,
            verifier_crs_len: reader.read_u32()?,
            resource_limits_version: reader.read_u32()?,
            gas_schedule_version: reader.read_u32()?,
            acir_digest: reader.read_array()?,
            artifact_digest: reader.read_array()?,
            vk_digest: reader.read_array()?,
            bb_vk_hash: reader.read_array()?,
            public_input_schema_digest: reader.read_array()?,
            verifier_crs_identifier_digest: reader.read_array()?,
            verifier_crs_encoding_digest: reader.read_array()?,
            verifier_crs_digest: reader.read_array()?,
            trusted_setup_provenance_digest: reader.read_array()?,
            g1_vk_generation_digest: reader.read_array()?,
            security_assumptions_digest: reader.read_array()?,
            abi_schema_vector_digest: reader.read_array()?,
            registry_entry_schema_digest: reader.read_array()?,
            resource_limits_digest: reader.read_array()?,
            gas_schedule_digest: reader.read_array()?,
            producer_toolchain_digest: reader.read_array()?,
        })
    }

    fn encode_into(
        &self,
        writer: &mut Writer<'_>,
    ) -> Result<(), ProfileCodecError> {
        writer.write(&self.discriminator)?;
        writer.write(&self.statement_domain)?;
        writer.write_u8(self.proof_system)?;
        writer.write_u8(self.curve)?;
        writer.write_u8(self.barretenberg_target)?;
        writer.write_u8(self.transcript)?;
        writer.write_u8(self.zero_knowledge)?;
        writer.write_u8(self.ipa_accumulation)?;
        writer.write_u32(self.proof_len)?;
        writer.write_u32(self.vk_len)?;
        writer.write_u32(self.public_inputs_len)?;
        writer.write_u32(self.public_input_arity)?;
        writer.write_u32(self.log_n)?;
        writer.write_u32(self.verifier_crs_len)?;
        writer.write_u32(self.resource_limits_version)?;
        writer.write_u32(self.gas_schedule_version)?;
        for (_, digest) in self.named_digests() {
            writer.write(digest)?;
        }
        Ok(())
    }

    fn named_digests(&self) -> [(&'static str, &[u8; 32]); 16] {
        [
            ("acir_digest", &self.acir_digest),
            ("artifact_digest", &self.artifact_digest),
            ("vk_digest", &self.vk_digest),
            ("bb_vk_hash", &self.bb_vk_hash),
            (
                "public_input_schema_digest",
                &self.public_input_schema_digest,
            ),
            (
                "verifier_crs_identifier_digest",
                &self.verifier_crs_identifier_digest,
            ),
            (
                "verifier_crs_encoding_digest",
                &self.verifier_crs_encoding_digest,
            ),
            ("verifier_crs_digest", &self.verifier_crs_digest),
            (
                "trusted_setup_provenance_digest",
                &self.trusted_setup_provenance_digest,
            ),
            ("g1_vk_generation_digest", &self.g1_vk_generation_digest),
            (
                "security_assumptions_digest",
                &self.security_assumptions_digest,
            ),
            ("abi_schema_vector_digest", &self.abi_schema_vector_digest),
            (
                "registry_entry_schema_digest",
                &self.registry_entry_schema_digest,
            ),
            ("resource_limits_digest", &self.resource_limits_digest),
            ("gas_schedule_digest", &self.gas_schedule_digest),
            ("producer_toolchain_digest", &self.producer_toolchain_digest),
        ]
    }
}

/// Canonical three-row profile allowlist.
///
/// The wire format contains a Borsh `Vec` prefix, but this in-memory shape uses
/// an array so no caller or decoder can represent an unbounded row count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitProfileAllowlistV1 {
    /// Exact schema version; must be one.
    pub schema_version: u32,
    /// SHA-256 digest of the profile identifier bytes.
    pub profile_identifier_digest: [u8; 32],
    /// Exactly three rows, strictly sorted by raw discriminator.
    pub entries: [CircuitProfileBindingV1; 3],
}

impl CircuitProfileAllowlistV1 {
    /// Decode and validate one exact three-row allowlist.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ProfileCodecError> {
        let mut reader = Reader::new(bytes);
        let schema_version = reader.read_u32()?;
        let profile_identifier_digest = reader.read_array()?;
        let entry_count = reader.read_u32()?;
        if entry_count != CIRCUIT_PROFILE_ENTRY_COUNT_V1 {
            return Err(ProfileCodecError::InvalidEntryCount {
                actual: entry_count,
            });
        }

        let entries = [
            CircuitProfileBindingV1::decode_from(&mut reader)?,
            CircuitProfileBindingV1::decode_from(&mut reader)?,
            CircuitProfileBindingV1::decode_from(&mut reader)?,
        ];
        reader.finish()?;

        let allowlist = Self {
            schema_version,
            profile_identifier_digest,
            entries,
        };
        allowlist.validate()?;
        Ok(allowlist)
    }

    /// Validate the exact schema, profile prefix, ordering, and circuit set.
    pub fn validate(&self) -> Result<(), ProfileCodecError> {
        validate_schema_version(
            "circuit profile allowlist",
            self.schema_version,
        )?;
        ensure_nonzero_bytes(
            "profile_identifier_digest",
            &self.profile_identifier_digest,
        )?;

        for entry in &self.entries {
            entry.validate_for_profile_identifier(
                &self.profile_identifier_digest,
            )?;
        }

        if !(self.entries[0].discriminator < self.entries[1].discriminator
            && self.entries[1].discriminator < self.entries[2].discriminator)
        {
            return Err(ProfileCodecError::EntriesNotStrictlySorted);
        }

        let codes = [
            self.entries[0].discriminator[32],
            self.entries[1].discriminator[32],
            self.entries[2].discriminator[32],
        ];
        if codes
            != [
                IMPORT_CIRCUIT_CODE,
                EXPORT_CIRCUIT_CODE,
                TRANSFER_CIRCUIT_CODE,
            ]
        {
            return Err(ProfileCodecError::InvalidCircuitCodeSet);
        }
        Ok(())
    }

    /// Encode one validated allowlist into its exact 1,885-byte wire form.
    pub fn to_bytes(
        &self,
    ) -> Result<[u8; CIRCUIT_PROFILE_ALLOWLIST_V1_ENCODED_LEN], ProfileCodecError>
    {
        self.validate()?;
        let mut bytes = [0_u8; CIRCUIT_PROFILE_ALLOWLIST_V1_ENCODED_LEN];
        let mut writer = Writer::new(&mut bytes);
        writer.write_u32(self.schema_version)?;
        writer.write(&self.profile_identifier_digest)?;
        writer.write_u32(CIRCUIT_PROFILE_ENTRY_COUNT_V1)?;
        for entry in &self.entries {
            entry.encode_into(&mut writer)?;
        }
        writer.finish()?;
        Ok(bytes)
    }

    /// Return the domain-separated SHA-256 digest of this canonical allowlist.
    pub fn digest(&self) -> Result<[u8; 32], ProfileCodecError> {
        circuit_profile_allowlist_digest(self)
    }
}

/// Canonical trusted-setup provenance digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedSetupProvenanceV1 {
    /// Exact schema version; must be one.
    pub schema_version: u32,
    /// Domain-separated digest of the canonical ceremony identifier.
    pub ceremony_identifier_digest: [u8; 32],
    /// Domain-separated digest of the canonical ceremony transcript.
    pub ceremony_transcript_digest: [u8; 32],
    /// Domain-separated digest of the canonical provenance source bundle.
    pub provenance_source_bundle_digest: [u8; 32],
}

impl TrustedSetupProvenanceV1 {
    /// Build a provenance record from the three published canonical byte sets.
    pub fn from_canonical_sources(
        ceremony_identifier_bytes: &[u8],
        canonical_transcript_bytes: &[u8],
        canonical_provenance_bundle_bytes: &[u8],
    ) -> Self {
        Self {
            schema_version: CIRCUIT_PROFILE_SCHEMA_VERSION_V1,
            ceremony_identifier_digest: ceremony_identifier_digest(
                ceremony_identifier_bytes,
            ),
            ceremony_transcript_digest: ceremony_transcript_digest(
                canonical_transcript_bytes,
            ),
            provenance_source_bundle_digest: provenance_source_bundle_digest(
                canonical_provenance_bundle_bytes,
            ),
        }
    }

    /// Decode and validate one exact 100-byte provenance record.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ProfileCodecError> {
        let mut reader = Reader::new(bytes);
        let provenance = Self {
            schema_version: reader.read_u32()?,
            ceremony_identifier_digest: reader.read_array()?,
            ceremony_transcript_digest: reader.read_array()?,
            provenance_source_bundle_digest: reader.read_array()?,
        };
        reader.finish()?;
        provenance.validate()?;
        Ok(provenance)
    }

    /// Validate the schema version and reject all-zero digest placeholders.
    pub fn validate(&self) -> Result<(), ProfileCodecError> {
        validate_schema_version(
            "trusted setup provenance",
            self.schema_version,
        )?;
        ensure_nonzero_bytes(
            "ceremony_identifier_digest",
            &self.ceremony_identifier_digest,
        )?;
        ensure_nonzero_bytes(
            "ceremony_transcript_digest",
            &self.ceremony_transcript_digest,
        )?;
        ensure_nonzero_bytes(
            "provenance_source_bundle_digest",
            &self.provenance_source_bundle_digest,
        )?;
        Ok(())
    }

    /// Verify all three digests against independently supplied canonical bytes.
    pub fn validate_against_sources(
        &self,
        ceremony_identifier_bytes: &[u8],
        canonical_transcript_bytes: &[u8],
        canonical_provenance_bundle_bytes: &[u8],
    ) -> Result<(), ProfileCodecError> {
        self.validate()?;
        if self.ceremony_identifier_digest
            != ceremony_identifier_digest(ceremony_identifier_bytes)
        {
            return Err(ProfileCodecError::DigestMismatch {
                field: "ceremony_identifier_digest",
            });
        }
        if self.ceremony_transcript_digest
            != ceremony_transcript_digest(canonical_transcript_bytes)
        {
            return Err(ProfileCodecError::DigestMismatch {
                field: "ceremony_transcript_digest",
            });
        }
        if self.provenance_source_bundle_digest
            != provenance_source_bundle_digest(
                canonical_provenance_bundle_bytes,
            )
        {
            return Err(ProfileCodecError::DigestMismatch {
                field: "provenance_source_bundle_digest",
            });
        }
        Ok(())
    }

    /// Encode one validated provenance record into exactly 100 bytes.
    pub fn to_bytes(
        &self,
    ) -> Result<[u8; TRUSTED_SETUP_PROVENANCE_V1_ENCODED_LEN], ProfileCodecError>
    {
        self.validate()?;
        let mut bytes = [0_u8; TRUSTED_SETUP_PROVENANCE_V1_ENCODED_LEN];
        let mut writer = Writer::new(&mut bytes);
        writer.write_u32(self.schema_version)?;
        writer.write(&self.ceremony_identifier_digest)?;
        writer.write(&self.ceremony_transcript_digest)?;
        writer.write(&self.provenance_source_bundle_digest)?;
        writer.finish()?;
        Ok(bytes)
    }

    /// Return the domain-separated digest of this canonical record.
    pub fn digest(&self) -> Result<[u8; 32], ProfileCodecError> {
        trusted_setup_provenance_digest(self)
    }
}

/// Protocol-version parameter selecting no allowlist or one allowlist digest.
///
/// Decoding `Some` only validates the wire shape and non-zero digest. This type
/// contains no method that stores or activates the selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveCircuitProfileAllowlistV1 {
    /// Exact schema version; must be one.
    pub schema_version: u32,
    /// `None` while profiles are inactive, or a separately reviewed allowlist digest.
    pub allowlist_digest: Option<[u8; 32]>,
}

impl ActiveCircuitProfileAllowlistV1 {
    /// Canonical initial fail-closed parameter value.
    pub const INACTIVE: Self = Self {
        schema_version: CIRCUIT_PROFILE_SCHEMA_VERSION_V1,
        allowlist_digest: None,
    };

    /// Decode and validate an exact five-byte `None` or 37-byte `Some` value.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ProfileCodecError> {
        let mut reader = Reader::new(bytes);
        let schema_version = reader.read_u32()?;
        let allowlist_digest = match reader.read_u8()? {
            0 => None,
            1 => Some(reader.read_array()?),
            tag => return Err(ProfileCodecError::InvalidOptionTag(tag)),
        };
        reader.finish()?;
        let active = Self {
            schema_version,
            allowlist_digest,
        };
        active.validate()?;
        Ok(active)
    }

    /// Validate the schema version and reject an all-zero selected digest.
    pub fn validate(&self) -> Result<(), ProfileCodecError> {
        validate_schema_version(
            "active circuit profile allowlist",
            self.schema_version,
        )?;
        if let Some(digest) = &self.allowlist_digest {
            ensure_nonzero_bytes("allowlist_digest", digest)?;
        }
        Ok(())
    }

    /// Encode the value into canonical Borsh option bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ProfileCodecError> {
        self.validate()?;
        let expected_len = if self.allowlist_digest.is_some() {
            ACTIVE_CIRCUIT_PROFILE_ALLOWLIST_V1_SOME_LEN
        } else {
            ACTIVE_CIRCUIT_PROFILE_ALLOWLIST_V1_NONE_LEN
        };
        let mut bytes = Vec::with_capacity(expected_len);
        bytes.extend_from_slice(&self.schema_version.to_le_bytes());
        match self.allowlist_digest {
            None => bytes.push(0),
            Some(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(&digest);
            }
        }
        if bytes.len() != expected_len {
            return Err(ProfileCodecError::InternalLengthMismatch);
        }
        Ok(bytes)
    }
}

/// Compute the profile allowlist's specified domain-separated digest.
pub fn circuit_profile_allowlist_digest(
    allowlist: &CircuitProfileAllowlistV1,
) -> Result<[u8; 32], ProfileCodecError> {
    Ok(domain_separated_sha256(
        ALLOWLIST_DIGEST_DOMAIN,
        &allowlist.to_bytes()?,
    ))
}

/// Compute a ceremony identifier's specified domain-separated digest.
pub fn ceremony_identifier_digest(
    canonical_identifier_bytes: &[u8],
) -> [u8; 32] {
    domain_separated_sha256(
        CEREMONY_IDENTIFIER_DIGEST_DOMAIN,
        canonical_identifier_bytes,
    )
}

/// Compute a ceremony transcript's specified domain-separated digest.
pub fn ceremony_transcript_digest(
    canonical_transcript_bytes: &[u8],
) -> [u8; 32] {
    domain_separated_sha256(
        CEREMONY_TRANSCRIPT_DIGEST_DOMAIN,
        canonical_transcript_bytes,
    )
}

/// Compute a provenance source bundle's specified domain-separated digest.
pub fn provenance_source_bundle_digest(
    canonical_bundle_bytes: &[u8],
) -> [u8; 32] {
    domain_separated_sha256(
        PROVENANCE_SOURCE_BUNDLE_DIGEST_DOMAIN,
        canonical_bundle_bytes,
    )
}

/// Compute the specified digest of a trusted-setup provenance record.
pub fn trusted_setup_provenance_digest(
    provenance: &TrustedSetupProvenanceV1,
) -> Result<[u8; 32], ProfileCodecError> {
    Ok(domain_separated_sha256(
        TRUSTED_SETUP_PROVENANCE_DIGEST_DOMAIN,
        &provenance.to_bytes()?,
    ))
}

/// Compute a verifier-CRS encoding artifact's specified domain-separated digest.
pub fn verifier_crs_encoding_digest(
    canonical_encoding_bytes: &[u8],
) -> [u8; 32] {
    domain_separated_sha256(
        VERIFIER_CRS_ENCODING_DIGEST_DOMAIN,
        canonical_encoding_bytes,
    )
}

fn domain_separated_sha256(domain: &[u8], canonical_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

fn statement_domain_for_code(code: u8) -> Result<[u8; 32], ProfileCodecError> {
    match code {
        IMPORT_CIRCUIT_CODE => Ok(IMPORT_STATEMENT_DOMAIN),
        EXPORT_CIRCUIT_CODE => Ok(EXPORT_STATEMENT_DOMAIN),
        TRANSFER_CIRCUIT_CODE => Ok(TRANSFER_STATEMENT_DOMAIN),
        _ => Err(ProfileCodecError::InvalidCircuitCode(code)),
    }
}

fn validate_schema_version(
    record: &'static str,
    version: u32,
) -> Result<(), ProfileCodecError> {
    if version != CIRCUIT_PROFILE_SCHEMA_VERSION_V1 {
        return Err(ProfileCodecError::InvalidSchemaVersion {
            record,
            actual: version,
        });
    }
    Ok(())
}

fn validate_tag(
    field: &'static str,
    actual: u8,
    expected: u8,
) -> Result<(), ProfileCodecError> {
    if actual != expected {
        return Err(ProfileCodecError::InvalidTag {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

fn ensure_nonzero_u32(
    field: &'static str,
    value: u32,
) -> Result<(), ProfileCodecError> {
    if value == 0 {
        return Err(ProfileCodecError::ZeroField { field });
    }
    Ok(())
}

fn ensure_nonzero_bytes(
    field: &'static str,
    value: &[u8],
) -> Result<(), ProfileCodecError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(ProfileCodecError::ZeroField { field });
    }
    Ok(())
}

fn ensure_max(
    field: &'static str,
    actual: u32,
    maximum: u32,
) -> Result<(), ProfileCodecError> {
    if actual > maximum {
        return Err(ProfileCodecError::LimitExceeded {
            field,
            maximum,
            actual,
        });
    }
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_array<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], ProfileCodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(ProfileCodecError::UnexpectedEnd)?;
        let source = self
            .bytes
            .get(self.position..end)
            .ok_or(ProfileCodecError::UnexpectedEnd)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(source);
        self.position = end;
        Ok(output)
    }

    fn read_u8(&mut self) -> Result<u8, ProfileCodecError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u32(&mut self) -> Result<u32, ProfileCodecError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn finish(self) -> Result<(), ProfileCodecError> {
        let remaining = self.bytes.len().saturating_sub(self.position);
        if remaining != 0 {
            return Err(ProfileCodecError::TrailingBytes { remaining });
        }
        Ok(())
    }
}

struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn write(&mut self, value: &[u8]) -> Result<(), ProfileCodecError> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(ProfileCodecError::InternalLengthMismatch)?;
        let destination = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(ProfileCodecError::InternalLengthMismatch)?;
        destination.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn write_u8(&mut self, value: u8) -> Result<(), ProfileCodecError> {
        self.write(&[value])
    }

    fn write_u32(&mut self, value: u32) -> Result<(), ProfileCodecError> {
        self.write(&value.to_le_bytes())
    }

    fn finish(self) -> Result<(), ProfileCodecError> {
        if self.position != self.bytes.len() {
            return Err(ProfileCodecError::InternalLengthMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE_IDENTIFIER_DIGEST: [u8; 32] = [0x42; 32];

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
        fn nibble(byte: u8) -> u8 {
            match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("golden fixture must use lowercase hexadecimal"),
            }
        }

        let bytes = hex.as_bytes();
        assert_eq!(bytes.len(), N * 2);
        let mut decoded = [0_u8; N];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            decoded[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
        }
        decoded
    }

    fn binding(code: u8) -> CircuitProfileBindingV1 {
        let mut discriminator = [0_u8; 33];
        discriminator[..32].copy_from_slice(&PROFILE_IDENTIFIER_DIGEST);
        discriminator[32] = code;
        CircuitProfileBindingV1 {
            discriminator,
            statement_domain: statement_domain_for_code(code).unwrap(),
            proof_system: 0,
            curve: 0,
            barretenberg_target: 0,
            transcript: 0,
            zero_knowledge: 1,
            ipa_accumulation: 0,
            proof_len: MAX_PROOF_V1_BYTES,
            vk_len: ULTRAHONK_VK_V1_BYTES,
            public_inputs_len: MAX_PUBLIC_INPUTS_V1_BYTES,
            public_input_arity: MAX_PUBLIC_INPUT_ARITY_V1,
            log_n: 16,
            verifier_crs_len: 128,
            resource_limits_version: 1,
            gas_schedule_version: 1,
            acir_digest: digest(1),
            artifact_digest: digest(2),
            vk_digest: digest(3),
            bb_vk_hash: digest(4),
            public_input_schema_digest: digest(5),
            verifier_crs_identifier_digest: digest(6),
            verifier_crs_encoding_digest: digest(7),
            verifier_crs_digest: digest(8),
            trusted_setup_provenance_digest: digest(9),
            g1_vk_generation_digest: digest(10),
            security_assumptions_digest: digest(11),
            abi_schema_vector_digest: digest(12),
            registry_entry_schema_digest: REGISTRY_ENTRY_SCHEMA_DIGEST_V1,
            resource_limits_digest: digest(14),
            gas_schedule_digest: digest(15),
            producer_toolchain_digest: digest(16),
        }
    }

    fn allowlist() -> CircuitProfileAllowlistV1 {
        CircuitProfileAllowlistV1 {
            schema_version: CIRCUIT_PROFILE_SCHEMA_VERSION_V1,
            profile_identifier_digest: PROFILE_IDENTIFIER_DIGEST,
            entries: [
                binding(IMPORT_CIRCUIT_CODE),
                binding(EXPORT_CIRCUIT_CODE),
                binding(TRANSFER_CIRCUIT_CODE),
            ],
        }
    }

    #[test]
    fn binding_has_exact_length_and_roundtrips() {
        let binding = binding(IMPORT_CIRCUIT_CODE);
        let bytes = binding.to_bytes().unwrap();
        assert_eq!(bytes.len(), CIRCUIT_PROFILE_BINDING_V1_ENCODED_LEN);
        assert_eq!(
            CircuitProfileBindingV1::try_from_slice(&bytes),
            Ok(binding)
        );
    }

    #[test]
    fn binding_matches_adr_0009_authoritative_golden_bytes() {
        // Exact `input.profile_binding` Borsh bytes from
        // `adr-0009-registry-entry-v1.vector.json` (raw fixture SHA-256
        // c69d633a6a70e04046ce9907354fa60a43939867118e679e6275b74e48aa5d96).
        let golden = decode_hex::<CIRCUIT_PROFILE_BINDING_V1_ENCODED_LEN>(
            concat!(
                "0d2be5a4b1fac6afbdad4d6160b6123411559e3931bba0324fbbb85aceb1e5eb",
                "013c385d28bdfc4964a27ef693c4dbfb23737008146beae63657ac30c312e72b",
                "70000000000100401c000060070000a0000000050000000c0000000100000001",
                "000000010000004a6b9d3cbf3c92565a00e957377f36532bcfa9bf4d3468e4f",
                "3aca6cdba6bd7d363269382782f3436dffeea27626a39399898580e52420d94b",
                "8b990ab26e3cbe60864e23b36d7d3c2828533375a59d690692c1a358c2da8c6",
                "869eb3a0154ef67ea5d1a85f757d8acc48c792b3dcb6219bcae7f4482689392",
                "e09b472212b4f009d8f098ecef1c321f57e255c9abb860294809c17a6a323952",
                "5ebef3da926788f67ecfd42126de6f1572d4e94b5dab50574b54abf3a8ede33",
                "34bf719b79a174a0f885de3e13432204db52b9c5e0be3b32c51573ae19b4542",
                "2ececaa5a62ad6a1e11bbeebd879e1dff6918546dc0c179fdde505f2a21591c",
                "9a9c96e36b054ec5af83a76d2401324e7c16cb90f3b99ce38add519397c2258",
                "82310876ccba55c5a586f1de99afe8b55676132dbbe7e3ac0cefa8be1154072a",
                "fafff6968b7c8f63a1c5e7f20f2d29ff27218bd30a9f406b286bd1f8505901",
                "8b783c5d21e0189e7d37ad053133176bee4d6ab1c9d7e57303b72a392e8bf42",
                "d88e255c6628b3d026cab4afb8dcb00e588257b83dd95d47de26a7be34fd903",
                "fc5f649834eb9e6b2dd607ae12dae5603c5ee527780e248e408acfef4a62b64",
                "ffab4f2e7189a1e0854ed4f8660d734caa5600c0339847a34ea7f936000aa7b",
                "b5077a35f9fa1a711d25b08078ad13829443bb5e6b3dbbc3f79ab7edf361548",
                "c908a1c417005fe51d6db75a3781",
            ),
        );

        let decoded = CircuitProfileBindingV1::try_from_slice(&golden).unwrap();
        assert_eq!(decoded.proof_len, MAX_PROOF_V1_BYTES);
        assert_eq!(decoded.to_bytes().unwrap(), golden);

        let mut over_limit = golden;
        const PROOF_LEN_OFFSET: usize = 71;
        over_limit[PROOF_LEN_OFFSET..PROOF_LEN_OFFSET + 4]
            .copy_from_slice(&(MAX_PROOF_V1_BYTES + 1).to_le_bytes());
        assert!(matches!(
            CircuitProfileBindingV1::try_from_slice(&over_limit),
            Err(ProfileCodecError::LimitExceeded {
                field: "proof_len",
                ..
            })
        ));
    }

    #[test]
    fn binding_rejects_every_truncation_and_trailing_bytes() {
        let bytes = binding(IMPORT_CIRCUIT_CODE).to_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(
                CircuitProfileBindingV1::try_from_slice(&bytes[..end]).is_err()
            );
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(matches!(
            CircuitProfileBindingV1::try_from_slice(&trailing),
            Err(ProfileCodecError::TrailingBytes { remaining: 1 })
        ));
    }

    #[test]
    fn binding_decoder_rejects_semantic_wire_mutations() {
        const DOMAIN_OFFSET: usize = 33;
        const PROOF_SYSTEM_OFFSET: usize = 65;
        const PROOF_LEN_OFFSET: usize = 71;
        const ACIR_DIGEST_OFFSET: usize = 103;

        let valid = binding(IMPORT_CIRCUIT_CODE).to_bytes().unwrap();

        let mut bad_code = valid;
        bad_code[32] = 4;
        assert_eq!(
            CircuitProfileBindingV1::try_from_slice(&bad_code),
            Err(ProfileCodecError::InvalidCircuitCode(4))
        );

        let mut bad_domain = valid;
        bad_domain[DOMAIN_OFFSET] ^= 1;
        assert!(matches!(
            CircuitProfileBindingV1::try_from_slice(&bad_domain),
            Err(ProfileCodecError::InvalidStatementDomain { .. })
        ));

        let mut bad_tag = valid;
        bad_tag[PROOF_SYSTEM_OFFSET] = 1;
        assert!(matches!(
            CircuitProfileBindingV1::try_from_slice(&bad_tag),
            Err(ProfileCodecError::InvalidTag {
                field: "proof_system",
                ..
            })
        ));

        let mut zero_length = valid;
        zero_length[PROOF_LEN_OFFSET..PROOF_LEN_OFFSET + 4].fill(0);
        assert!(matches!(
            CircuitProfileBindingV1::try_from_slice(&zero_length),
            Err(ProfileCodecError::ZeroField { field: "proof_len" })
        ));

        let mut zero_digest = valid;
        zero_digest[ACIR_DIGEST_OFFSET..ACIR_DIGEST_OFFSET + 32].fill(0);
        assert!(matches!(
            CircuitProfileBindingV1::try_from_slice(&zero_digest),
            Err(ProfileCodecError::ZeroField {
                field: "acir_digest"
            })
        ));
    }

    #[test]
    fn allowlist_has_exact_length_digest_and_roundtrips() {
        let allowlist = allowlist();
        let bytes = allowlist.to_bytes().unwrap();
        assert_eq!(bytes.len(), CIRCUIT_PROFILE_ALLOWLIST_V1_ENCODED_LEN);
        assert_eq!(
            CircuitProfileAllowlistV1::try_from_slice(&bytes),
            Ok(allowlist)
        );

        let expected = domain_separated_sha256(ALLOWLIST_DIGEST_DOMAIN, &bytes);
        assert_eq!(allowlist.digest().unwrap(), expected);
    }

    #[test]
    fn allowlist_rejects_every_truncation_trailing_and_bad_vector_lengths() {
        let bytes = allowlist().to_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(
                CircuitProfileAllowlistV1::try_from_slice(&bytes[..end])
                    .is_err()
            );
        }

        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(matches!(
            CircuitProfileAllowlistV1::try_from_slice(&trailing),
            Err(ProfileCodecError::TrailingBytes { remaining: 1 })
        ));

        for bad_count in [0, 1, 2, 4, u32::MAX] {
            let mut malformed = bytes;
            malformed[36..40].copy_from_slice(&bad_count.to_le_bytes());
            assert_eq!(
                CircuitProfileAllowlistV1::try_from_slice(&malformed),
                Err(ProfileCodecError::InvalidEntryCount { actual: bad_count })
            );
        }

        // The hostile vector prefix is rejected from the small outer buffer;
        // the decoder never reserves storage proportional to the prefix.
        let mut hostile_small_input = [0_u8; 40];
        hostile_small_input[..4].copy_from_slice(&1_u32.to_le_bytes());
        hostile_small_input[4..36].fill(1);
        hostile_small_input[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            CircuitProfileAllowlistV1::try_from_slice(&hostile_small_input),
            Err(ProfileCodecError::InvalidEntryCount { actual: u32::MAX })
        );
    }

    #[test]
    fn allowlist_rejects_profile_mismatch_duplicates_order_and_code_set() {
        let mut candidate = allowlist();
        candidate.schema_version = 0;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::InvalidSchemaVersion { .. })
        ));

        let mut candidate = allowlist();
        candidate.profile_identifier_digest = [0; 32];
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::ZeroField {
                field: "profile_identifier_digest"
            })
        ));

        let mut candidate = allowlist();
        candidate.entries[1].discriminator[..32].fill(0x43);
        assert_eq!(
            candidate.validate(),
            Err(ProfileCodecError::ProfileIdentifierMismatch)
        );

        let mut candidate = allowlist();
        candidate.entries[1] = candidate.entries[0];
        assert!(candidate.validate().is_err());

        let mut candidate = allowlist();
        candidate.entries.swap(0, 1);
        assert_eq!(
            candidate.validate(),
            Err(ProfileCodecError::EntriesNotStrictlySorted)
        );

        let mut candidate = allowlist();
        candidate.entries[1].discriminator[32] = TRANSFER_CIRCUIT_CODE;
        candidate.entries[1].statement_domain = TRANSFER_STATEMENT_DOMAIN;
        assert!(candidate.validate().is_err());

        let mut candidate = allowlist();
        candidate.entries[1].discriminator[32] = 4;
        assert_eq!(
            candidate.validate(),
            Err(ProfileCodecError::InvalidCircuitCode(4))
        );
    }

    #[test]
    fn binding_rejects_wrong_domain_and_every_bad_fixed_tag() {
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.statement_domain = EXPORT_STATEMENT_DOMAIN;
        assert_eq!(
            candidate.validate(),
            Err(ProfileCodecError::InvalidStatementDomain {
                circuit_code: IMPORT_CIRCUIT_CODE
            })
        );

        let mut candidates = Vec::new();
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.proof_system = 1;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.curve = 1;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.barretenberg_target = 1;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.transcript = 1;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.zero_knowledge = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.ipa_accumulation = 1;
        candidates.push(candidate);
        for candidate in candidates {
            assert!(matches!(
                candidate.validate(),
                Err(ProfileCodecError::InvalidTag { .. })
            ));
        }
    }

    #[test]
    fn binding_rejects_zero_scalar_fields() {
        let mut candidates = Vec::new();
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.proof_len = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.vk_len = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.public_inputs_len = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.public_input_arity = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.log_n = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.verifier_crs_len = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.resource_limits_version = 0;
        candidates.push(candidate);
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.gas_schedule_version = 0;
        candidates.push(candidate);
        for candidate in candidates {
            assert!(matches!(
                candidate.validate(),
                Err(ProfileCodecError::ZeroField { .. })
            ));
        }

        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.discriminator[..32].fill(0);
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::ZeroField {
                field: "discriminator profile prefix"
            })
        ));
    }

    #[test]
    fn binding_rejects_every_zero_digest() {
        for digest_index in 0..16 {
            let mut candidate = binding(IMPORT_CIRCUIT_CODE);
            match digest_index {
                0 => candidate.acir_digest = [0; 32],
                1 => candidate.artifact_digest = [0; 32],
                2 => candidate.vk_digest = [0; 32],
                3 => candidate.bb_vk_hash = [0; 32],
                4 => candidate.public_input_schema_digest = [0; 32],
                5 => candidate.verifier_crs_identifier_digest = [0; 32],
                6 => candidate.verifier_crs_encoding_digest = [0; 32],
                7 => candidate.verifier_crs_digest = [0; 32],
                8 => candidate.trusted_setup_provenance_digest = [0; 32],
                9 => candidate.g1_vk_generation_digest = [0; 32],
                10 => candidate.security_assumptions_digest = [0; 32],
                11 => candidate.abi_schema_vector_digest = [0; 32],
                12 => candidate.registry_entry_schema_digest = [0; 32],
                13 => candidate.resource_limits_digest = [0; 32],
                14 => candidate.gas_schedule_digest = [0; 32],
                15 => candidate.producer_toolchain_digest = [0; 32],
                _ => unreachable!(),
            }
            assert!(matches!(
                candidate.validate(),
                Err(ProfileCodecError::ZeroField { .. })
            ));
        }

        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.registry_entry_schema_digest = digest(99);
        assert_eq!(
            candidate.validate(),
            Err(ProfileCodecError::DigestMismatch {
                field: "registry_entry_schema_digest"
            })
        );
    }

    #[test]
    fn binding_enforces_proof_vk_public_input_and_crs_bounds() {
        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.proof_len = MAX_PROOF_V1_BYTES;
        candidate.verifier_crs_len = MAX_VERIFIER_CRS_V1_BYTES;
        assert_eq!(candidate.validate(), Ok(()));

        candidate.proof_len = MAX_PROOF_V1_BYTES + 1;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::LimitExceeded {
                field: "proof_len",
                ..
            })
        ));

        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.vk_len = ULTRAHONK_VK_V1_BYTES - 1;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::InvalidVkLength { .. })
        ));

        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.public_inputs_len = MAX_PUBLIC_INPUTS_V1_BYTES + 1;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::LimitExceeded {
                field: "public_inputs_len",
                ..
            })
        ));

        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.public_input_arity = MAX_PUBLIC_INPUT_ARITY_V1 + 1;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::LimitExceeded {
                field: "public_input_arity",
                ..
            })
        ));

        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.public_inputs_len = 128;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::InvalidPublicInputLength { .. })
        ));

        let mut candidate = binding(IMPORT_CIRCUIT_CODE);
        candidate.verifier_crs_len = MAX_VERIFIER_CRS_V1_BYTES + 1;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::LimitExceeded {
                field: "verifier_crs_len",
                ..
            })
        ));
    }

    #[test]
    fn trusted_setup_has_exact_length_roundtrips_and_binds_sources() {
        let provenance = TrustedSetupProvenanceV1::from_canonical_sources(
            b"ceremony",
            b"transcript",
            b"source bundle",
        );
        let bytes = provenance.to_bytes().unwrap();
        assert_eq!(bytes.len(), TRUSTED_SETUP_PROVENANCE_V1_ENCODED_LEN);
        assert_eq!(
            TrustedSetupProvenanceV1::try_from_slice(&bytes),
            Ok(provenance)
        );
        assert_eq!(
            provenance.validate_against_sources(
                b"ceremony",
                b"transcript",
                b"source bundle"
            ),
            Ok(())
        );
        assert!(matches!(
            provenance.validate_against_sources(
                b"another ceremony",
                b"transcript",
                b"source bundle"
            ),
            Err(ProfileCodecError::DigestMismatch {
                field: "ceremony_identifier_digest"
            })
        ));
        assert_ne!(
            provenance.digest().unwrap(),
            verifier_crs_encoding_digest(&bytes)
        );
    }

    #[test]
    fn trusted_setup_rejects_truncation_trailing_bad_version_and_zeros() {
        let provenance =
            TrustedSetupProvenanceV1::from_canonical_sources(b"a", b"b", b"c");
        let bytes = provenance.to_bytes().unwrap();
        for end in 0..bytes.len() {
            assert!(
                TrustedSetupProvenanceV1::try_from_slice(&bytes[..end])
                    .is_err()
            );
        }
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(matches!(
            TrustedSetupProvenanceV1::try_from_slice(&trailing),
            Err(ProfileCodecError::TrailingBytes { remaining: 1 })
        ));

        let mut candidate = provenance;
        candidate.schema_version = 2;
        assert!(matches!(
            candidate.validate(),
            Err(ProfileCodecError::InvalidSchemaVersion { .. })
        ));
        for field in 0..3 {
            let mut candidate = provenance;
            match field {
                0 => candidate.ceremony_identifier_digest = [0; 32],
                1 => candidate.ceremony_transcript_digest = [0; 32],
                2 => candidate.provenance_source_bundle_digest = [0; 32],
                _ => unreachable!(),
            }
            assert!(matches!(
                candidate.validate(),
                Err(ProfileCodecError::ZeroField { .. })
            ));
        }
    }

    #[test]
    fn active_allowlist_none_and_some_have_exact_canonical_encodings() {
        let none = ActiveCircuitProfileAllowlistV1::INACTIVE;
        let none_bytes = none.to_bytes().unwrap();
        assert_eq!(none_bytes, [1, 0, 0, 0, 0]);
        assert_eq!(
            ActiveCircuitProfileAllowlistV1::try_from_slice(&none_bytes),
            Ok(none)
        );

        let some = ActiveCircuitProfileAllowlistV1 {
            schema_version: CIRCUIT_PROFILE_SCHEMA_VERSION_V1,
            allowlist_digest: Some(digest(7)),
        };
        let some_bytes = some.to_bytes().unwrap();
        assert_eq!(
            some_bytes.len(),
            ACTIVE_CIRCUIT_PROFILE_ALLOWLIST_V1_SOME_LEN
        );
        assert_eq!(some_bytes[4], 1);
        assert_eq!(
            ActiveCircuitProfileAllowlistV1::try_from_slice(&some_bytes),
            Ok(some)
        );
    }

    #[test]
    fn active_allowlist_rejects_bad_tags_lengths_versions_and_zero_digest() {
        for malformed in [
            Vec::new(),
            vec![1, 0, 0, 0],
            vec![1, 0, 0, 0, 0, 0],
            vec![1, 0, 0, 0, 1],
            vec![1, 0, 0, 0, 2],
        ] {
            assert!(
                ActiveCircuitProfileAllowlistV1::try_from_slice(&malformed)
                    .is_err()
            );
        }

        let invalid_version = [2, 0, 0, 0, 0];
        assert!(matches!(
            ActiveCircuitProfileAllowlistV1::try_from_slice(&invalid_version),
            Err(ProfileCodecError::InvalidSchemaVersion { .. })
        ));

        let mut zero_some = vec![1, 0, 0, 0, 1];
        zero_some.extend_from_slice(&[0; 32]);
        assert_eq!(
            ActiveCircuitProfileAllowlistV1::try_from_slice(&zero_some),
            Err(ProfileCodecError::ZeroField {
                field: "allowlist_digest"
            })
        );
    }

    #[test]
    fn digest_helpers_are_domain_separated() {
        let bytes = b"same canonical bytes";
        let digests = [
            ceremony_identifier_digest(bytes),
            ceremony_transcript_digest(bytes),
            provenance_source_bundle_digest(bytes),
            verifier_crs_encoding_digest(bytes),
        ];
        for left in 0..digests.len() {
            for right in left + 1..digests.len() {
                assert_ne!(digests[left], digests[right]);
            }
        }
    }
}
