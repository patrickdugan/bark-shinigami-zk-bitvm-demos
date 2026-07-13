//! Canonical statement encoding for the showcase security boundary.
//!
//! This format is deliberately independent of JSON and Rust's `serde` data
//! model. Every integer is little-endian, every variable-size field is
//! `u32_le length || bytes`, and the decoder rejects trailing bytes.

use ark::bitcoin::hashes::{sha256, Hash};

const MAGIC: &[u8; 4] = b"BZBV";
const VERSION: u16 = 1;
const MAX_VTXO_BYTES: usize = 1 << 20;
const MAX_TRANSACTION_BYTES: usize = 4 << 20;
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_OUTCOME_BYTES: usize = 256;
const MAX_PREVOUTS: usize = 4_096;
const MAX_PAYOUTS: usize = 4_096;
const MAX_ENVELOPE_BYTES: usize = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    OwnerExit = 1,
    VirtualCet = 2,
}

impl TryFrom<u8> for ClaimKind {
    type Error = EnvelopeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::OwnerExit),
            2 => Ok(Self::VirtualCet),
            _ => Err(EnvelopeError::InvalidClaimKind(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prevout {
    pub amount_sats: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payout {
    pub amount_sats: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleEvidence {
    OwnerExit {
        owner_xonly: [u8; 32],
        csv_delay: u32,
    },
    VirtualCet {
        event_id: [u8; 32],
        oracle_xonly: [u8; 32],
        announcement_signature: [u8; 64],
        attestation_signature: [u8; 64],
        outcome: Vec<u8>,
        payouts: Vec<Payout>,
    },
}

impl RoleEvidence {
    fn kind(&self) -> ClaimKind {
        match self {
            Self::OwnerExit { .. } => ClaimKind::OwnerExit,
            Self::VirtualCet { .. } => ClaimKind::VirtualCet,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactPins {
    pub shinigami_program: [u8; 32],
    pub cairo_program: [u8; 32],
    pub stwo_policy: [u8; 32],
    pub risc0_image_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarkSpendEnvelopeV1 {
    pub network_genesis: [u8; 32],
    pub contract_nonce: [u8; 32],
    pub vtxo_id: [u8; 36],
    pub protocol_vtxo: Vec<u8>,
    pub anchor_transaction: Vec<u8>,
    pub spend_transaction: Vec<u8>,
    pub input_index: u32,
    pub prevouts: Vec<Prevout>,
    pub chain_height: u32,
    pub prevout_confirmed_height: u32,
    pub script_flags: u32,
    pub evidence: RoleEvidence,
    pub pins: ArtifactPins,
}

impl BarkSpendEnvelopeV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate_limits()?;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        put_u16(&mut out, VERSION);
        out.push(self.evidence.kind() as u8);
        out.extend_from_slice(&self.network_genesis);
        out.extend_from_slice(&self.contract_nonce);
        out.extend_from_slice(&self.vtxo_id);
        put_bytes(&mut out, &self.protocol_vtxo)?;
        put_bytes(&mut out, &self.anchor_transaction)?;
        put_bytes(&mut out, &self.spend_transaction)?;
        put_u32(&mut out, self.input_index);
        put_u32(&mut out, usize_to_u32(self.prevouts.len())?);
        for prevout in &self.prevouts {
            put_u64(&mut out, prevout.amount_sats);
            put_bytes(&mut out, &prevout.script_pubkey)?;
        }
        put_u32(&mut out, self.chain_height);
        put_u32(&mut out, self.prevout_confirmed_height);
        put_u32(&mut out, self.script_flags);
        self.encode_evidence(&mut out)?;
        out.extend_from_slice(&self.pins.shinigami_program);
        out.extend_from_slice(&self.pins.cairo_program);
        out.extend_from_slice(&self.pins.stwo_policy);
        out.extend_from_slice(&self.pins.risc0_image_id);
        if out.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::Oversized("envelope"));
        }
        Ok(out)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, EnvelopeError> {
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::Oversized("envelope"));
        }
        let mut reader = Reader::new(encoded);
        if reader.array::<4>()? != *MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        let version = reader.u16()?;
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion(version));
        }
        let claim_kind = ClaimKind::try_from(reader.u8()?)?;
        let network_genesis = reader.array()?;
        let contract_nonce = reader.array()?;
        let vtxo_id = reader.array()?;
        let protocol_vtxo = reader.bytes(MAX_VTXO_BYTES, "VTXO")?;
        let anchor_transaction = reader.bytes(MAX_TRANSACTION_BYTES, "anchor transaction")?;
        let spend_transaction = reader.bytes(MAX_TRANSACTION_BYTES, "spend transaction")?;
        let input_index = reader.u32()?;
        let prevout_count = reader.count(MAX_PREVOUTS, "prevouts")?;
        let mut prevouts = Vec::with_capacity(prevout_count);
        for _ in 0..prevout_count {
            prevouts.push(Prevout {
                amount_sats: reader.u64()?,
                script_pubkey: reader.bytes(MAX_SCRIPT_BYTES, "prevout script")?,
            });
        }
        let chain_height = reader.u32()?;
        let prevout_confirmed_height = reader.u32()?;
        let script_flags = reader.u32()?;
        let evidence = match claim_kind {
            ClaimKind::OwnerExit => RoleEvidence::OwnerExit {
                owner_xonly: reader.array()?,
                csv_delay: reader.u32()?,
            },
            ClaimKind::VirtualCet => {
                let event_id = reader.array()?;
                let oracle_xonly = reader.array()?;
                let announcement_signature = reader.array()?;
                let attestation_signature = reader.array()?;
                let outcome = reader.bytes(MAX_OUTCOME_BYTES, "oracle outcome")?;
                let payout_count = reader.count(MAX_PAYOUTS, "payouts")?;
                let mut payouts = Vec::with_capacity(payout_count);
                for _ in 0..payout_count {
                    payouts.push(Payout {
                        amount_sats: reader.u64()?,
                        script_pubkey: reader.bytes(MAX_SCRIPT_BYTES, "payout script")?,
                    });
                }
                RoleEvidence::VirtualCet {
                    event_id,
                    oracle_xonly,
                    announcement_signature,
                    attestation_signature,
                    outcome,
                    payouts,
                }
            }
        };
        let pins = ArtifactPins {
            shinigami_program: reader.array()?,
            cairo_program: reader.array()?,
            stwo_policy: reader.array()?,
            risc0_image_id: reader.array()?,
        };
        if !reader.is_finished() {
            return Err(EnvelopeError::TrailingBytes);
        }
        let envelope = Self {
            network_genesis,
            contract_nonce,
            vtxo_id,
            protocol_vtxo,
            anchor_transaction,
            spend_transaction,
            input_index,
            prevouts,
            chain_height,
            prevout_confirmed_height,
            script_flags,
            evidence,
            pins,
        };
        envelope.validate_limits()?;
        Ok(envelope)
    }

    pub fn statement_digest(&self) -> Result<[u8; 32], EnvelopeError> {
        Ok(tagged_sha256("BarkZkBitvm/StatementV1", &self.encode()?))
    }

    fn validate_limits(&self) -> Result<(), EnvelopeError> {
        check_len(self.protocol_vtxo.len(), MAX_VTXO_BYTES, "VTXO")?;
        check_len(
            self.anchor_transaction.len(),
            MAX_TRANSACTION_BYTES,
            "anchor transaction",
        )?;
        check_len(
            self.spend_transaction.len(),
            MAX_TRANSACTION_BYTES,
            "spend transaction",
        )?;
        check_len(self.prevouts.len(), MAX_PREVOUTS, "prevouts")?;
        for prevout in &self.prevouts {
            check_len(
                prevout.script_pubkey.len(),
                MAX_SCRIPT_BYTES,
                "prevout script",
            )?;
        }
        match &self.evidence {
            RoleEvidence::OwnerExit { .. } => {}
            RoleEvidence::VirtualCet {
                outcome, payouts, ..
            } => {
                check_len(outcome.len(), MAX_OUTCOME_BYTES, "oracle outcome")?;
                check_len(payouts.len(), MAX_PAYOUTS, "payouts")?;
                for payout in payouts {
                    check_len(
                        payout.script_pubkey.len(),
                        MAX_SCRIPT_BYTES,
                        "payout script",
                    )?;
                }
            }
        }
        Ok(())
    }

    fn encode_evidence(&self, out: &mut Vec<u8>) -> Result<(), EnvelopeError> {
        match &self.evidence {
            RoleEvidence::OwnerExit {
                owner_xonly,
                csv_delay,
            } => {
                out.extend_from_slice(owner_xonly);
                put_u32(out, *csv_delay);
            }
            RoleEvidence::VirtualCet {
                event_id,
                oracle_xonly,
                announcement_signature,
                attestation_signature,
                outcome,
                payouts,
            } => {
                out.extend_from_slice(event_id);
                out.extend_from_slice(oracle_xonly);
                out.extend_from_slice(announcement_signature);
                out.extend_from_slice(attestation_signature);
                put_bytes(out, outcome)?;
                put_u32(out, usize_to_u32(payouts.len())?);
                for payout in payouts {
                    put_u64(out, payout.amount_sats);
                    put_bytes(out, &payout.script_pubkey)?;
                }
            }
        }
        Ok(())
    }
}

pub fn tagged_sha256(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(tag_hash.as_byte_array());
    preimage.extend_from_slice(message);
    sha256::Hash::hash(&preimage).to_byte_array()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    UnexpectedEof,
    BadMagic,
    UnsupportedVersion(u16),
    InvalidClaimKind(u8),
    Oversized(&'static str),
    LengthOverflow,
    TrailingBytes,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of envelope"),
            Self::BadMagic => write!(f, "invalid envelope magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported envelope version {version}")
            }
            Self::InvalidClaimKind(kind) => write!(f, "invalid claim kind {kind}"),
            Self::Oversized(field) => write!(f, "{field} exceeds its canonical size limit"),
            Self::LengthOverflow => write!(f, "length does not fit in u32"),
            Self::TrailingBytes => write!(f, "trailing bytes are not canonical"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

fn check_len(actual: usize, maximum: usize, field: &'static str) -> Result<(), EnvelopeError> {
    if actual > maximum {
        Err(EnvelopeError::Oversized(field))
    } else {
        Ok(())
    }
}

fn usize_to_u32(value: usize) -> Result<u32, EnvelopeError> {
    u32::try_from(value).map_err(|_| EnvelopeError::LengthOverflow)
}

fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), EnvelopeError> {
    put_u32(out, usize_to_u32(value.len())?);
    out.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], EnvelopeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(EnvelopeError::UnexpectedEof)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EnvelopeError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| EnvelopeError::UnexpectedEof)
    }

    fn u8(&mut self) -> Result<u8, EnvelopeError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, EnvelopeError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, EnvelopeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, EnvelopeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn count(&mut self, maximum: usize, field: &'static str) -> Result<usize, EnvelopeError> {
        let value = usize::try_from(self.u32()?).map_err(|_| EnvelopeError::LengthOverflow)?;
        check_len(value, maximum, field)?;
        Ok(value)
    }

    fn bytes(&mut self, maximum: usize, field: &'static str) -> Result<Vec<u8>, EnvelopeError> {
        let len = self.count(maximum, field)?;
        Ok(self.take(len)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BarkSpendEnvelopeV1 {
        BarkSpendEnvelopeV1 {
            network_genesis: [1; 32],
            contract_nonce: [2; 32],
            vtxo_id: [3; 36],
            protocol_vtxo: vec![4, 5, 6],
            anchor_transaction: vec![7, 8],
            spend_transaction: vec![9, 10],
            input_index: 0,
            prevouts: vec![Prevout {
                amount_sats: 42,
                script_pubkey: vec![0x51],
            }],
            chain_height: 300,
            prevout_confirmed_height: 100,
            script_flags: 0xdead_beef,
            evidence: RoleEvidence::OwnerExit {
                owner_xonly: [11; 32],
                csv_delay: 144,
            },
            pins: ArtifactPins {
                shinigami_program: [12; 32],
                cairo_program: [13; 32],
                stwo_policy: [14; 32],
                risc0_image_id: [15; 32],
            },
        }
    }

    #[test]
    fn canonical_round_trip() {
        let envelope = sample();
        let encoded = envelope.encode().unwrap();
        assert_eq!(BarkSpendEnvelopeV1::decode(&encoded).unwrap(), envelope);
        assert_eq!(
            BarkSpendEnvelopeV1::decode(&encoded)
                .unwrap()
                .encode()
                .unwrap(),
            encoded
        );
    }

    #[test]
    fn rejects_trailing_unknown_fields() {
        let mut encoded = sample().encode().unwrap();
        encoded.push(0);
        assert_eq!(
            BarkSpendEnvelopeV1::decode(&encoded),
            Err(EnvelopeError::TrailingBytes)
        );
    }

    #[test]
    fn digest_binds_every_byte() {
        let encoded = sample().encode().unwrap();
        let expected = sample().statement_digest().unwrap();
        for index in 0..encoded.len() {
            let mut changed = encoded.clone();
            changed[index] ^= 1;
            if let Ok(decoded) = BarkSpendEnvelopeV1::decode(&changed) {
                assert_ne!(
                    decoded.statement_digest().unwrap(),
                    expected,
                    "byte {index} was not bound"
                );
            }
        }
    }
}
