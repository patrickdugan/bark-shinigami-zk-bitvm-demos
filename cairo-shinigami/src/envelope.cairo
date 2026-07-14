const MAX_VTXO_BYTES: usize = 0x100000;
const MAX_TRANSACTION_BYTES: usize = 0x400000;
const MAX_SCRIPT_BYTES: usize = 10000;
const MAX_OUTCOME_BYTES: usize = 256;
const MAX_PREVOUTS: usize = 4096;
const MAX_PAYOUTS: usize = 4096;
const MAX_ENVELOPE_BYTES: usize = 0x1000000;

pub const OWNER_EXIT_KIND: u8 = 1;
pub const VIRTUAL_CET_KIND: u8 = 2;

#[derive(Clone, Drop)]
pub struct PrevoutV1 {
    pub amount_sats: u64,
    pub script_pubkey: ByteArray,
}

#[derive(Clone, Drop)]
pub struct PayoutV1 {
    pub amount_sats: u64,
    pub script_pubkey: ByteArray,
}

#[derive(Clone, Drop)]
pub struct OwnerExitEvidenceV1 {
    pub owner_xonly: ByteArray,
    pub csv_delay: u32,
}

#[derive(Clone, Drop)]
pub struct VirtualCetEvidenceV1 {
    pub event_id: ByteArray,
    pub oracle_xonly: ByteArray,
    pub announcement_signature: ByteArray,
    pub attestation_signature: ByteArray,
    pub outcome: ByteArray,
    pub payouts: Array<PayoutV1>,
}

#[derive(Clone, Drop)]
pub enum RoleEvidenceV1 {
    OwnerExit: OwnerExitEvidenceV1,
    VirtualCet: VirtualCetEvidenceV1,
}

#[derive(Clone, Drop)]
pub struct ArtifactPinsV1 {
    pub shinigami_program: ByteArray,
    pub cairo_program: ByteArray,
    pub stwo_policy: ByteArray,
    pub risc0_image_id: ByteArray,
}

#[derive(Clone, Drop)]
pub struct BarkSpendEnvelopeV1 {
    pub claim_kind: u8,
    pub network_genesis: ByteArray,
    pub contract_nonce: ByteArray,
    pub vtxo_id: ByteArray,
    pub protocol_vtxo: ByteArray,
    pub anchor_transaction: ByteArray,
    pub spend_transaction: ByteArray,
    pub input_index: u32,
    pub prevouts: Array<PrevoutV1>,
    pub chain_height: u32,
    pub prevout_confirmed_height: u32,
    pub script_flags: u32,
    pub evidence: RoleEvidenceV1,
    pub pins: ArtifactPinsV1,
}

/// Decode the exact Rust `BarkSpendEnvelopeV1` wire format. Any malformed,
/// oversized, non-canonical, or trailing input aborts execution and therefore
/// cannot produce an accepting STWO proof.
pub fn decode(encoded: @ByteArray) -> BarkSpendEnvelopeV1 {
    assert(encoded.len() <= MAX_ENVELOPE_BYTES, 'envelope too large');
    let mut offset: usize = 0;
    assert(read_exact(encoded, ref offset, 4) == "BZBV", 'bad envelope magic');
    assert(read_u16_le(encoded, ref offset) == 1, 'bad envelope version');
    let claim_kind = read_u8(encoded, ref offset);
    assert(claim_kind == OWNER_EXIT_KIND || claim_kind == VIRTUAL_CET_KIND, 'bad claim kind');

    let network_genesis = read_exact(encoded, ref offset, 32);
    let contract_nonce = read_exact(encoded, ref offset, 32);
    assert(any_nonzero(@contract_nonce), 'zero contract nonce');
    let vtxo_id = read_exact(encoded, ref offset, 36);
    let protocol_vtxo = read_sized(encoded, ref offset, MAX_VTXO_BYTES);
    let anchor_transaction = read_sized(encoded, ref offset, MAX_TRANSACTION_BYTES);
    let spend_transaction = read_sized(encoded, ref offset, MAX_TRANSACTION_BYTES);
    let input_index = read_u32_le(encoded, ref offset);

    let prevout_count: usize = read_u32_le(encoded, ref offset).try_into().unwrap();
    assert(prevout_count <= MAX_PREVOUTS, 'too many prevouts');
    let mut prevouts: Array<PrevoutV1> = array![];
    let mut prevout_index: usize = 0;
    while prevout_index < prevout_count {
        prevouts
            .append(
                PrevoutV1 {
                    amount_sats: read_u64_le(encoded, ref offset),
                    script_pubkey: read_sized(encoded, ref offset, MAX_SCRIPT_BYTES),
                },
            );
        prevout_index += 1;
    }

    let chain_height = read_u32_le(encoded, ref offset);
    let prevout_confirmed_height = read_u32_le(encoded, ref offset);
    let script_flags = read_u32_le(encoded, ref offset);

    let evidence = if claim_kind == OWNER_EXIT_KIND {
        RoleEvidenceV1::OwnerExit(
            OwnerExitEvidenceV1 {
                owner_xonly: read_exact(encoded, ref offset, 32),
                csv_delay: read_u32_le(encoded, ref offset),
            },
        )
    } else {
        let event_id = read_exact(encoded, ref offset, 32);
        let oracle_xonly = read_exact(encoded, ref offset, 32);
        let announcement_signature = read_exact(encoded, ref offset, 64);
        let attestation_signature = read_exact(encoded, ref offset, 64);
        let outcome = read_sized(encoded, ref offset, MAX_OUTCOME_BYTES);
        let payout_count: usize = read_u32_le(encoded, ref offset).try_into().unwrap();
        assert(payout_count <= MAX_PAYOUTS, 'too many payouts');
        let mut payouts: Array<PayoutV1> = array![];
        let mut payout_index: usize = 0;
        while payout_index < payout_count {
            payouts
                .append(
                    PayoutV1 {
                        amount_sats: read_u64_le(encoded, ref offset),
                        script_pubkey: read_sized(encoded, ref offset, MAX_SCRIPT_BYTES),
                    },
                );
            payout_index += 1;
        }
        RoleEvidenceV1::VirtualCet(
            VirtualCetEvidenceV1 {
                event_id,
                oracle_xonly,
                announcement_signature,
                attestation_signature,
                outcome,
                payouts,
            },
        )
    };

    let pins = ArtifactPinsV1 {
        shinigami_program: read_exact(encoded, ref offset, 32),
        cairo_program: read_exact(encoded, ref offset, 32),
        stwo_policy: read_exact(encoded, ref offset, 32),
        risc0_image_id: read_exact(encoded, ref offset, 32),
    };
    assert(offset == encoded.len(), 'trailing envelope bytes');

    BarkSpendEnvelopeV1 {
        claim_kind,
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
    }
}

fn ensure_available(encoded: @ByteArray, offset: usize, length: usize) {
    assert(offset <= encoded.len(), 'envelope offset overflow');
    assert(length <= encoded.len() - offset, 'truncated envelope');
}

fn read_u8(encoded: @ByteArray, ref offset: usize) -> u8 {
    ensure_available(encoded, offset, 1);
    let value = encoded[offset];
    offset += 1;
    value
}

fn read_u16_le(encoded: @ByteArray, ref offset: usize) -> u16 {
    ensure_available(encoded, offset, 2);
    let value: u16 = encoded[offset].into() + encoded[offset + 1].into() * 0x100;
    offset += 2;
    value
}

fn read_u32_le(encoded: @ByteArray, ref offset: usize) -> u32 {
    ensure_available(encoded, offset, 4);
    let value: u32 = encoded[offset].into()
        + encoded[offset
        + 1].into() * 0x100
        + encoded[offset
        + 2].into() * 0x10000
        + encoded[offset
        + 3].into() * 0x1000000;
    offset += 4;
    value
}

fn read_u64_le(encoded: @ByteArray, ref offset: usize) -> u64 {
    ensure_available(encoded, offset, 8);
    let mut value: u64 = 0;
    let mut index: usize = 0;
    let mut multiplier: u64 = 1;
    while index < 8 {
        value += encoded[offset + index].into() * multiplier;
        if index < 7 {
            multiplier *= 0x100;
        }
        index += 1;
    }
    offset += 8;
    value
}

fn read_sized(encoded: @ByteArray, ref offset: usize, maximum: usize) -> ByteArray {
    let length: usize = read_u32_le(encoded, ref offset).try_into().unwrap();
    assert(length <= maximum, 'oversized envelope field');
    read_exact(encoded, ref offset, length)
}

fn read_exact(encoded: @ByteArray, ref offset: usize, length: usize) -> ByteArray {
    ensure_available(encoded, offset, length);
    let mut value: ByteArray = "";
    let mut index: usize = 0;
    while index < length {
        value.append_byte(encoded[offset + index]);
        index += 1;
    }
    offset += length;
    value
}

fn any_nonzero(bytes: @ByteArray) -> bool {
    let mut index: usize = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return true;
        }
        index += 1;
    }
    false
}
