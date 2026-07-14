//! Canonical byte-level contract shared by the future RISC Zero guest and its
//! host. Parsing and hashing this contract does not prove a STWO statement;
//! only the guest may construct it after cryptographic verification.

use core::fmt;

use sha2::{Digest, Sha256};

pub const INPUT_VERSION: u32 = 1;
pub const MAX_EXECUTABLE_BYTES: usize = 4 << 20;
pub const MAX_ENVELOPE_BYTES: usize = 16 << 20;
pub const MAX_COMPRESSED_PROOF_BYTES: usize = 8 << 20;
pub const BINDING_RECORD_BYTES: usize = 378;

const ENVELOPE_MAGIC: [u8; 4] = *b"BZBV";
const ENVELOPE_VERSION: u16 = 1;
const MAX_VTXO_BYTES: usize = 1 << 20;
const MAX_TRANSACTION_BYTES: usize = 4 << 20;
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_OUTCOME_BYTES: usize = 256;
const MAX_PREVOUTS: usize = 4_096;
const MAX_PAYOUTS: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalInputError {
    UnexpectedEof,
    UnsupportedInputVersion(u32),
    UnsupportedEnvelopeVersion(u16),
    InvalidEnvelopeMagic,
    InvalidClaimKind(u8),
    Oversized(&'static str),
    LengthOverflow,
    TrailingBytes,
    ZeroContractNonce,
    ZeroRisc0ImageId,
    Risc0ImageIdMismatch,
}

impl fmt::Display for CanonicalInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of canonical input"),
            Self::UnsupportedInputVersion(version) => {
                write!(f, "unsupported RISC Zero input version {version}")
            }
            Self::UnsupportedEnvelopeVersion(version) => {
                write!(f, "unsupported Bark envelope version {version}")
            }
            Self::InvalidEnvelopeMagic => write!(f, "invalid Bark envelope magic"),
            Self::InvalidClaimKind(kind) => write!(f, "invalid Bark claim kind {kind}"),
            Self::Oversized(field) => write!(f, "{field} exceeds its canonical limit"),
            Self::LengthOverflow => write!(f, "canonical length overflows this target"),
            Self::TrailingBytes => write!(f, "trailing bytes are not canonical"),
            Self::ZeroContractNonce => write!(f, "contract nonce must not be zero"),
            Self::ZeroRisc0ImageId => write!(f, "RISC Zero image ID must not be zero"),
            Self::Risc0ImageIdMismatch => {
                write!(f, "envelope RISC Zero image ID does not match guest input")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CanonicalInputError {}

/// Borrowed, allocation-free view of the exact guest input frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Risc0StwoInputV1<'a> {
    pub executable: &'a [u8],
    pub envelope: &'a [u8],
    pub compressed_stwo_proof: &'a [u8],
    pub expected_risc0_image_id: [u8; 32],
}

impl<'a> Risc0StwoInputV1<'a> {
    pub fn decode(encoded: &'a [u8]) -> Result<Self, CanonicalInputError> {
        let mut reader = Reader::new(encoded);
        let version = reader.u32()?;
        if version != INPUT_VERSION {
            return Err(CanonicalInputError::UnsupportedInputVersion(version));
        }
        let executable = reader.len_prefixed_u32(MAX_EXECUTABLE_BYTES, "Cairo executable")?;
        let envelope = reader.len_prefixed_u32(MAX_ENVELOPE_BYTES, "Bark envelope")?;
        let proof_len = reader.u64()?;
        let proof_len =
            usize::try_from(proof_len).map_err(|_| CanonicalInputError::LengthOverflow)?;
        if proof_len > MAX_COMPRESSED_PROOF_BYTES {
            return Err(CanonicalInputError::Oversized("compressed STWO proof"));
        }
        let compressed_stwo_proof = reader.take(proof_len)?;
        let expected_risc0_image_id = reader.array()?;
        if expected_risc0_image_id == [0; 32] {
            return Err(CanonicalInputError::ZeroRisc0ImageId);
        }
        reader.finish()?;
        Ok(Self {
            executable,
            envelope,
            compressed_stwo_proof,
            expected_risc0_image_id,
        })
    }

    /// Decode the complete envelope and perform the image-ID handshake in one
    /// typed operation so a guest cannot accidentally validate the two values
    /// independently and forget to compare them.
    pub fn bound_envelope(&self) -> Result<BarkEnvelopeBindingV1, CanonicalInputError> {
        let binding = BarkEnvelopeBindingV1::decode(self.envelope)?;
        if binding.risc0_image_id != self.expected_risc0_image_id {
            return Err(CanonicalInputError::Risc0ImageIdMismatch);
        }
        Ok(binding)
    }
}

/// Fields needed to bind a canonical Bark envelope to the outer proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarkEnvelopeBindingV1 {
    pub contract_nonce: [u8; 32],
    pub stwo_policy_digest: [u8; 32],
    pub risc0_image_id: [u8; 32],
}

impl BarkEnvelopeBindingV1 {
    pub fn decode(encoded: &[u8]) -> Result<Self, CanonicalInputError> {
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(CanonicalInputError::Oversized("Bark envelope"));
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<4>()? != ENVELOPE_MAGIC {
            return Err(CanonicalInputError::InvalidEnvelopeMagic);
        }
        let version = reader.u16()?;
        if version != ENVELOPE_VERSION {
            return Err(CanonicalInputError::UnsupportedEnvelopeVersion(version));
        }
        let claim_kind = reader.u8()?;
        if !matches!(claim_kind, 1 | 2) {
            return Err(CanonicalInputError::InvalidClaimKind(claim_kind));
        }
        reader.skip(32)?; // network genesis
        let contract_nonce = reader.array()?;
        if contract_nonce == [0; 32] {
            return Err(CanonicalInputError::ZeroContractNonce);
        }
        reader.skip(36)?; // VTXO id
        reader.len_prefixed_u32(MAX_VTXO_BYTES, "protocol VTXO")?;
        reader.len_prefixed_u32(MAX_TRANSACTION_BYTES, "anchor transaction")?;
        reader.len_prefixed_u32(MAX_TRANSACTION_BYTES, "spend transaction")?;
        reader.skip(4)?; // input index
        let prevout_count = reader.count(MAX_PREVOUTS, "prevouts")?;
        for _ in 0..prevout_count {
            reader.skip(8)?; // amount
            reader.len_prefixed_u32(MAX_SCRIPT_BYTES, "prevout script")?;
        }
        reader.skip(12)?; // three height/flag u32 values
        match claim_kind {
            1 => reader.skip(32 + 4)?,
            2 => {
                reader.skip(32 + 32 + 64 + 64)?;
                reader.len_prefixed_u32(MAX_OUTCOME_BYTES, "oracle outcome")?;
                let payout_count = reader.count(MAX_PAYOUTS, "payouts")?;
                for _ in 0..payout_count {
                    reader.skip(8)?;
                    reader.len_prefixed_u32(MAX_SCRIPT_BYTES, "payout script")?;
                }
            }
            _ => unreachable!("claim kind checked above"),
        }
        reader.skip(32)?; // Shinigami program pin
        reader.skip(32)?; // Cairo program pin
        let stwo_policy_digest = reader.array()?;
        let risc0_image_id = reader.array()?;
        reader.finish()?;
        Ok(Self {
            contract_nonce,
            stwo_policy_digest,
            risc0_image_id,
        })
    }
}

/// Fixed-width audit record committed by `Risc0StwoJournalV1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Risc0StwoBindingV1 {
    pub stwo_cairo_git_commit: [u8; 20],
    pub public_segment_patch_sha256: [u8; 32],
    pub executable_sha256: [u8; 32],
    pub stwo_program_hash_be: [u8; 32],
    pub stwo_policy_digest: [u8; 32],
    pub compressed_proof_len: u64,
    pub compressed_proof_sha256: [u8; 32],
    pub envelope_len: u32,
    pub envelope_sha256: [u8; 32],
    pub contract_nonce: [u8; 32],
    pub bark_statement_digest: [u8; 32],
    pub output_prefix: [u32; 3],
    pub full_output_sha256: [u8; 32],
    pub expected_risc0_image_id: [u8; 32],
}

impl Risc0StwoBindingV1 {
    pub const MAGIC: [u8; 8] = *b"BARKSTO1";
    pub const VERSION: u16 = 1;
    pub const OUTPUT_SCHEMA: u16 = 3;
    pub const OUTPUT_WORD_COUNT: u16 = 19;

    pub fn encode(&self) -> [u8; BINDING_RECORD_BYTES] {
        let mut encoded = [0u8; BINDING_RECORD_BYTES];
        let mut writer = FixedWriter::new(&mut encoded);
        writer.put(&Self::MAGIC);
        writer.put(&Self::VERSION.to_le_bytes());
        writer.put(&self.stwo_cairo_git_commit);
        writer.put(&self.public_segment_patch_sha256);
        writer.put(&self.executable_sha256);
        writer.put(&self.stwo_program_hash_be);
        writer.put(&self.stwo_policy_digest);
        writer.put(&self.compressed_proof_len.to_le_bytes());
        writer.put(&self.compressed_proof_sha256);
        writer.put(&self.envelope_len.to_le_bytes());
        writer.put(&self.envelope_sha256);
        writer.put(&self.contract_nonce);
        writer.put(&self.bark_statement_digest);
        writer.put(&Self::OUTPUT_SCHEMA.to_le_bytes());
        writer.put(&Self::OUTPUT_WORD_COUNT.to_le_bytes());
        for word in self.output_prefix {
            writer.put(&word.to_be_bytes());
        }
        writer.put(&self.full_output_sha256);
        writer.put(&self.expected_risc0_image_id);
        debug_assert_eq!(writer.offset, BINDING_RECORD_BYTES);
        encoded
    }

    pub fn journal(&self) -> [u8; 32] {
        tagged_sha256("BarkZkBitvm/Risc0StwoJournalV1", &self.encode())
    }
}

pub fn tagged_sha256(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash: [u8; 32] = Sha256::digest(tag.as_bytes()).into();
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn output_sha256(words: &[u32; 19]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for word in words {
        hasher.update(word.to_be_bytes());
    }
    hasher.finalize().into()
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CanonicalInputError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CanonicalInputError::UnexpectedEof)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CanonicalInputError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }

    fn skip(&mut self, len: usize) -> Result<(), CanonicalInputError> {
        self.take(len).map(|_| ())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CanonicalInputError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CanonicalInputError::UnexpectedEof)
    }

    fn u8(&mut self) -> Result<u8, CanonicalInputError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, CanonicalInputError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CanonicalInputError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CanonicalInputError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn count(&mut self, maximum: usize, field: &'static str) -> Result<usize, CanonicalInputError> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| CanonicalInputError::LengthOverflow)?;
        if count > maximum {
            return Err(CanonicalInputError::Oversized(field));
        }
        Ok(count)
    }

    fn len_prefixed_u32(
        &mut self,
        maximum: usize,
        field: &'static str,
    ) -> Result<&'a [u8], CanonicalInputError> {
        let len = self.count(maximum, field)?;
        self.take(len)
    }

    fn finish(self) -> Result<(), CanonicalInputError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CanonicalInputError::TrailingBytes)
        }
    }
}

struct FixedWriter<'a> {
    bytes: &'a mut [u8],
    offset: usize,
}

impl<'a> FixedWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn put(&mut self, value: &[u8]) {
        let end = self.offset + value.len();
        self.bytes[self.offset..end].copy_from_slice(value);
        self.offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut decoded = [0u8; N];
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        decoded
    }

    fn owner_envelope(nonce: [u8; 32], policy: [u8; 32], image: [u8; 32]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"BZBV");
        encoded.extend_from_slice(&1u16.to_le_bytes());
        encoded.push(1);
        encoded.extend_from_slice(&[1; 32]);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&[2; 36]);
        for value in [&[3u8][..], &[4u8][..], &[5u8][..]] {
            encoded.extend_from_slice(&(value.len() as u32).to_le_bytes());
            encoded.extend_from_slice(value);
        }
        encoded.extend_from_slice(&0u32.to_le_bytes());
        encoded.extend_from_slice(&1u32.to_le_bytes());
        encoded.extend_from_slice(&10_000u64.to_le_bytes());
        encoded.extend_from_slice(&1u32.to_le_bytes());
        encoded.push(0x51);
        encoded.extend_from_slice(&100u32.to_le_bytes());
        encoded.extend_from_slice(&90u32.to_le_bytes());
        encoded.extend_from_slice(&0x11010u32.to_le_bytes());
        encoded.extend_from_slice(&[6; 32]);
        encoded.extend_from_slice(&2016u32.to_le_bytes());
        encoded.extend_from_slice(&[7; 32]);
        encoded.extend_from_slice(&[8; 32]);
        encoded.extend_from_slice(&policy);
        encoded.extend_from_slice(&image);
        encoded
    }

    fn frame(executable: &[u8], envelope: &[u8], proof: &[u8], image: [u8; 32]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&INPUT_VERSION.to_le_bytes());
        encoded.extend_from_slice(&(executable.len() as u32).to_le_bytes());
        encoded.extend_from_slice(executable);
        encoded.extend_from_slice(&(envelope.len() as u32).to_le_bytes());
        encoded.extend_from_slice(envelope);
        encoded.extend_from_slice(&(proof.len() as u64).to_le_bytes());
        encoded.extend_from_slice(proof);
        encoded.extend_from_slice(&image);
        encoded
    }

    #[test]
    fn parses_exact_frame_and_envelope_bindings() {
        let image = [0x44; 32];
        let policy = [0x33; 32];
        let nonce = [0x22; 32];
        let envelope = owner_envelope(nonce, policy, image);
        let encoded = frame(b"executable", &envelope, b"proof", image);
        let input = Risc0StwoInputV1::decode(&encoded).unwrap();
        assert_eq!(input.executable, b"executable");
        assert_eq!(input.compressed_stwo_proof, b"proof");
        assert_eq!(
            input.bound_envelope().unwrap(),
            BarkEnvelopeBindingV1 {
                contract_nonce: nonce,
                stwo_policy_digest: policy,
                risc0_image_id: image,
            }
        );
    }

    #[test]
    fn rejects_trailing_zero_and_malformed_nested_lengths() {
        let image = [1; 32];
        let envelope = owner_envelope([2; 32], [3; 32], image);
        let mut encoded = frame(b"e", &envelope, b"p", image);
        encoded.push(0);
        assert_eq!(
            Risc0StwoInputV1::decode(&encoded),
            Err(CanonicalInputError::TrailingBytes)
        );

        let mut malformed = envelope;
        // First variable field begins after the fixed 107-byte prefix.
        malformed[107..111].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            BarkEnvelopeBindingV1::decode(&malformed),
            Err(CanonicalInputError::Oversized("protocol VTXO"))
        );
    }

    #[test]
    fn rejects_zero_nonce_and_zero_image() {
        let envelope = owner_envelope([0; 32], [3; 32], [1; 32]);
        assert_eq!(
            BarkEnvelopeBindingV1::decode(&envelope),
            Err(CanonicalInputError::ZeroContractNonce)
        );
        let encoded = frame(b"e", &envelope, b"p", [0; 32]);
        assert_eq!(
            Risc0StwoInputV1::decode(&encoded),
            Err(CanonicalInputError::ZeroRisc0ImageId)
        );
    }

    #[test]
    fn rejects_stale_or_substituted_envelope_image() {
        let envelope = owner_envelope([2; 32], [3; 32], [4; 32]);
        let encoded = frame(b"e", &envelope, b"p", [5; 32]);
        let input = Risc0StwoInputV1::decode(&encoded).unwrap();
        assert_eq!(
            input.bound_envelope(),
            Err(CanonicalInputError::Risc0ImageIdMismatch)
        );
    }

    #[test]
    fn binding_record_is_fixed_width_and_every_field_changes_journal() {
        let base = Risc0StwoBindingV1 {
            stwo_cairo_git_commit: [1; 20],
            public_segment_patch_sha256: [2; 32],
            executable_sha256: [3; 32],
            stwo_program_hash_be: [4; 32],
            stwo_policy_digest: [5; 32],
            compressed_proof_len: 6,
            compressed_proof_sha256: [7; 32],
            envelope_len: 8,
            envelope_sha256: [9; 32],
            contract_nonce: [10; 32],
            bark_statement_digest: [11; 32],
            output_prefix: [1, 0, 0],
            full_output_sha256: [12; 32],
            expected_risc0_image_id: [13; 32],
        };
        assert_eq!(base.encode().len(), BINDING_RECORD_BYTES);
        let expected = base.journal();
        let mut changed = base;
        changed.expected_risc0_image_id[31] ^= 1;
        assert_ne!(changed.journal(), expected);
        changed = base;
        changed.output_prefix[2] = 1;
        assert_ne!(changed.journal(), expected);
        changed = base;
        changed.compressed_proof_len += 1;
        assert_ne!(changed.journal(), expected);
    }

    #[test]
    fn matches_outer_adapter_golden_vector() {
        let binding = Risc0StwoBindingV1 {
            stwo_cairo_git_commit: hex("b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1"),
            public_segment_patch_sha256: hex(
                "ed5027b67ee3798ef2f1467604816cc5efb8e44cedf6083d329ae8f8e4227a71",
            ),
            executable_sha256: [0x11; 32],
            stwo_program_hash_be: hex(
                "00bcd09f617edcfc9ee2bbbb74192f42dfed6b7a505578a3748ac93f8ad697f0",
            ),
            stwo_policy_digest: hex(
                "cc48a057589ddbcf51c8458db65640609f21dac3afa485f717089806567dbece",
            ),
            compressed_proof_len: 1_117_271,
            compressed_proof_sha256: [0x22; 32],
            envelope_len: 4_096,
            envelope_sha256: [0x33; 32],
            contract_nonce: [0x44; 32],
            bark_statement_digest: [0x55; 32],
            output_prefix: [1, 0, 0],
            full_output_sha256: [0x66; 32],
            expected_risc0_image_id: [0x77; 32],
        };
        assert_eq!(
            sha256(&binding.encode()),
            hex("e4c8b299035a296c72f87801a36d9d84627d1756ffed1b3eb2004c48e10bebe4")
        );
        assert_eq!(
            binding.journal(),
            hex("cd8c15e1660af722cca79283386181c8bc5115077426e8d37feedb89a3eaba39")
        );
    }
}
