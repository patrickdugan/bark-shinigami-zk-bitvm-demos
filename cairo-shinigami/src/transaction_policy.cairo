use shinigami_engine::hash_cache::SigHashMidstateTrait;
use shinigami_engine::hash_tag::{HashTag, tagged_hash};
use shinigami_engine::signature::constants::SIG_HASH_DEFAULT;
use shinigami_engine::signature::sighash::{TaprootSighashOptionsTrait, calc_taproot_signature_hash};
use shinigami_engine::transaction::{
    EngineInternalTransactionTrait, EngineTransaction, EngineTransactionOutput, UTXO,
};
use shinigami_utils::bytecode::hex_to_bytecode;
use shinigami_utils::hash::sha256_byte_array;
use crate::envelope::BarkSpendEnvelopeV1;

const MAX_OUTPUTS: usize = 4096;
const MAX_SCRIPT_BYTES: usize = 10000;
const REQUIRED_SCRIPT_FLAGS: u32 = 0x11010;
const EXPECTED_CSV_DELAY: u32 = 2016;

#[derive(Drop)]
pub struct ValidatedSpendV1 {
    pub owner_signature: ByteArray,
    pub owner_public_key: ByteArray,
    pub taproot_sighash: u256,
    pub outputs: Array<EngineTransactionOutput>,
}

/// Validate the exact transaction profile used by the showcase and compute its
/// BIP341 script-path digest through Shinigami. A strict pre-parser runs before
/// Shinigami's generic decoder so its currently permissive length handling can
/// never turn truncation, non-canonical CompactSize, or trailing bytes into an
/// accepting statement.
pub fn validate_and_sighash(envelope: @BarkSpendEnvelopeV1) -> ValidatedSpendV1 {
    assert(
        envelope
            .network_genesis == @hex_to_bytecode(
                @"0x06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
            ),
        'network genesis mismatch',
    );
    assert(
        envelope
            .vtxo_id == @hex_to_bytecode(
                @"0x24e9a421d9018690eea79b11e4e4fe59d36aa8f46d110017e09abe350b5e315600000000",
            ),
        'showcase vtxo mismatch',
    );
    assert(
        sha256_byte_array(
            envelope.protocol_vtxo,
        ) == hex_to_bytecode(@"0x621bd7065d91b7901fc42ee0ba8e515352f0713c01142c36a175ce74ec8f6f48"),
        'protocol vtxo mismatch',
    );
    assert(
        sha256_byte_array(
            envelope.anchor_transaction,
        ) == hex_to_bytecode(@"0x6ee5df26b6f235ece4f316a713db3a84f3fbf432cf20595e146170875e191331"),
        'anchor transaction mismatch',
    );
    assert(
        envelope
            .pins
            .shinigami_program == @hex_to_bytecode(
                @"0xecc0d445cc1b42155db22e927623592d453046de4b5ac020cd90eedb46e1e5c5",
            ),
        'Shinigami pin mismatch',
    );
    assert(
        envelope
            .pins
            .cairo_program == @hex_to_bytecode(
                @"0xc56dcc4083b288b1799f8d7c3cbd49cec0a41a20242047400036a3b70e6d6b4f",
            ),
        'Cairo relation pin mismatch',
    );
    assert(
        envelope
            .pins
            .stwo_policy == @hex_to_bytecode(
                @"0xcc48a057589ddbcf51c8458db65640609f21dac3afa485f717089806567dbece",
            ),
        'STWO policy pin mismatch',
    );
    assert(*envelope.input_index == 0, 'input index must be zero');
    assert(envelope.prevouts.len() == 1, 'one prevout required');
    assert(*envelope.script_flags == REQUIRED_SCRIPT_FLAGS, 'script flags mismatch');
    assert(*envelope.chain_height >= *envelope.prevout_confirmed_height, 'height order invalid');
    assert(
        *envelope.chain_height - *envelope.prevout_confirmed_height >= EXPECTED_CSV_DELAY,
        'csv not mature',
    );

    let prevout = envelope.prevouts.at(0);
    assert(*prevout.amount_sats <= 0x7fffffffffffffff, 'prevout amount range');
    assert(
        prevout
            .script_pubkey == @hex_to_bytecode(
                @"0x5120e2b1152658195dae2fb792bdf7adb276e1c21f06b33588b9bd8429591bb964ea",
            ),
        'unexpected Bark prevout',
    );

    let raw = envelope.spend_transaction;
    let mut offset: usize = 0;
    let version = read_u32_le(raw, ref offset);
    assert(version == 2, 'transaction version');
    assert(read_u8(raw, ref offset) == 0, 'segwit marker');
    assert(read_u8(raw, ref offset) == 1, 'segwit flag');
    assert(read_compact_size(raw, ref offset) == 1, 'one input required');

    let outpoint = read_exact(raw, ref offset, 36);
    assert(@outpoint == envelope.vtxo_id, 'outpoint vtxo mismatch');
    assert(read_compact_size(raw, ref offset) == 0, 'scriptsig must be empty');
    let sequence = read_u32_le(raw, ref offset);
    assert(sequence & 0x80000000 == 0, 'csv disabled');
    assert(sequence & 0x00400000 == 0, 'time csv disallowed');
    assert(sequence & 0xffff >= EXPECTED_CSV_DELAY, 'sequence below csv');

    let output_count: usize = read_compact_size(raw, ref offset).try_into().unwrap();
    assert(output_count > 0 && output_count <= MAX_OUTPUTS, 'output count');
    let mut strict_outputs: Array<EngineTransactionOutput> = array![];
    let mut output_sum: u64 = 0;
    let mut output_index: usize = 0;
    while output_index < output_count {
        let value = read_u64_le(raw, ref offset);
        assert(value <= *prevout.amount_sats - output_sum, 'outputs exceed prevout');
        output_sum += value;
        let script_length: usize = read_compact_size(raw, ref offset).try_into().unwrap();
        assert(script_length <= MAX_SCRIPT_BYTES, 'output script too large');
        let script = read_exact(raw, ref offset, script_length);
        strict_outputs
            .append(
                EngineTransactionOutput {
                    value: value.try_into().unwrap(), publickey_script: script,
                },
            );
        output_index += 1;
    }

    assert(read_compact_size(raw, ref offset) == 3, 'witness item count');
    assert(read_compact_size(raw, ref offset) == 64, 'schnorr signature length');
    let owner_signature = read_exact(raw, ref offset, 64);
    let tapscript_length: usize = read_compact_size(raw, ref offset).try_into().unwrap();
    assert(tapscript_length == 39, 'owner tapscript length');
    let tapscript = read_exact(raw, ref offset, tapscript_length);
    validate_owner_tapscript(@tapscript);
    let control_length: usize = read_compact_size(raw, ref offset).try_into().unwrap();
    assert(control_length == 33, 'control block length');
    let control_block = read_exact(raw, ref offset, control_length);
    assert(
        control_block == hex_to_bytecode(
            @"0xc07db2187a69f1a4fc7685e2a32e70583701d5ca90f554a3aa26cd45827cb1ab2b",
        ),
        'unexpected Bark control',
    );
    let locktime = read_u32_le(raw, ref offset);
    assert(locktime == 0, 'locktime profile');
    assert(offset == raw.len(), 'trailing transaction bytes');

    // Cross-check every parsed field against Shinigami's transaction model.
    let utxo = UTXO {
        amount: (*prevout.amount_sats).try_into().unwrap(),
        pubkey_script: prevout.script_pubkey.clone(),
        block_height: *envelope.prevout_confirmed_height,
    };
    let transaction: EngineTransaction = EngineInternalTransactionTrait::deserialize(
        envelope.spend_transaction.clone(), 0, array![utxo],
    );
    assert(transaction.version == 2, 'Shinigami version mismatch');
    assert(transaction.transaction_inputs.len() == 1, 'Shinigami input mismatch');
    let shinigami_input = transaction.transaction_inputs.at(0);
    assert(shinigami_input.signature_script.len() == 0, 'Shinigami scriptsig mismatch');
    assert(*shinigami_input.sequence == sequence, 'Shinigami sequence mismatch');
    assert(shinigami_input.witness.len() == 3, 'Shinigami witness mismatch');
    assert(shinigami_input.witness.at(0) == @owner_signature, 'Shinigami signature mismatch');
    assert(shinigami_input.witness.at(1) == @tapscript, 'Shinigami script mismatch');
    assert(shinigami_input.witness.at(2) == @control_block, 'Shinigami control mismatch');
    assert(transaction.transaction_outputs.len() == strict_outputs.len(), 'Shinigami outputs');
    let mut compare_index: usize = 0;
    while compare_index < strict_outputs.len() {
        let strict_output = strict_outputs.at(compare_index);
        let shinigami_output = transaction.transaction_outputs.at(compare_index);
        assert(strict_output.value == shinigami_output.value, 'Shinigami amount mismatch');
        assert(
            strict_output.publickey_script == shinigami_output.publickey_script,
            'Shinigami script mismatch',
        );
        compare_index += 1;
    }
    assert(transaction.locktime == locktime, 'Shinigami locktime mismatch');

    let mut tapleaf_message: ByteArray = "";
    tapleaf_message.append_byte(0xc0);
    tapleaf_message.append_byte(tapscript_length.try_into().unwrap());
    tapleaf_message.append(@tapscript);
    let tapleaf_hash = tagged_hash(HashTag::TapLeaf, @tapleaf_message);
    let tapleaf_hash_bytes = u256_to_byte_array(tapleaf_hash);
    let sig_hashes = SigHashMidstateTrait::new(@transaction);
    let previous_output = EngineTransactionOutput {
        value: (*prevout.amount_sats).try_into().unwrap(),
        publickey_script: prevout.script_pubkey.clone(),
    };
    let mut options = TaprootSighashOptionsTrait::new_with_tapscript_version(
        0xffffffff, @tapleaf_hash_bytes,
    );
    let taproot_sighash = calc_taproot_signature_hash(
        sig_hashes, SIG_HASH_DEFAULT, @transaction, 0, previous_output, ref options,
    )
        .expect('Shinigami sighash');

    ValidatedSpendV1 {
        owner_signature,
        owner_public_key: slice(@tapscript, 6, 32),
        taproot_sighash,
        outputs: strict_outputs,
    }
}

fn validate_owner_tapscript(script: @ByteArray) {
    assert(script[0] == 2, 'csv push size');
    assert(script[1] == 0xe0 && script[2] == 0x07, 'csv script value');
    assert(script[3] == 0xb2 && script[4] == 0x75, 'csv script opcodes');
    assert(script[5] == 0x20 && script[38] == 0xac, 'owner script shape');
    assert(
        slice(
            script, 6, 32,
        ) == hex_to_bytecode(@"0x0a752219f1b94bbdf8994a0a980cdda08c2ad094cb29dd834878db6dee1612ee"),
        'unexpected Bark owner',
    );
}

pub fn u256_words(value: u256) -> [u32; 8] {
    let mask: u128 = 0xffffffff;
    [
        (value.high / 0x1000000000000000000000000).try_into().unwrap(),
        ((value.high / 0x10000000000000000) & mask).try_into().unwrap(),
        ((value.high / 0x100000000) & mask).try_into().unwrap(),
        (value.high & mask).try_into().unwrap(),
        (value.low / 0x1000000000000000000000000).try_into().unwrap(),
        ((value.low / 0x10000000000000000) & mask).try_into().unwrap(),
        ((value.low / 0x100000000) & mask).try_into().unwrap(),
        (value.low & mask).try_into().unwrap(),
    ]
}

fn u256_to_byte_array(value: u256) -> ByteArray {
    let mut bytes: ByteArray = "";
    bytes.append_word(value.high.into(), 16);
    bytes.append_word(value.low.into(), 16);
    bytes
}

fn ensure_available(raw: @ByteArray, offset: usize, length: usize) {
    assert(offset <= raw.len(), 'transaction offset');
    assert(length <= raw.len() - offset, 'truncated transaction');
}

fn read_u8(raw: @ByteArray, ref offset: usize) -> u8 {
    ensure_available(raw, offset, 1);
    let value = raw[offset];
    offset += 1;
    value
}

fn read_u16_le(raw: @ByteArray, ref offset: usize) -> u16 {
    ensure_available(raw, offset, 2);
    let value: u16 = raw[offset].into() + raw[offset + 1].into() * 0x100;
    offset += 2;
    value
}

fn read_u32_le(raw: @ByteArray, ref offset: usize) -> u32 {
    ensure_available(raw, offset, 4);
    let mut value: u32 = 0;
    let mut index: usize = 0;
    let mut multiplier: u32 = 1;
    while index < 4 {
        value += raw[offset + index].into() * multiplier;
        if index < 3 {
            multiplier *= 0x100;
        }
        index += 1;
    }
    offset += 4;
    value
}

fn read_u64_le(raw: @ByteArray, ref offset: usize) -> u64 {
    ensure_available(raw, offset, 8);
    let mut value: u64 = 0;
    let mut index: usize = 0;
    let mut multiplier: u64 = 1;
    while index < 8 {
        value += raw[offset + index].into() * multiplier;
        if index < 7 {
            multiplier *= 0x100;
        }
        index += 1;
    }
    offset += 8;
    value
}

fn read_compact_size(raw: @ByteArray, ref offset: usize) -> u64 {
    let prefix = read_u8(raw, ref offset);
    if prefix < 0xfd {
        prefix.into()
    } else if prefix == 0xfd {
        let value: u64 = read_u16_le(raw, ref offset).into();
        assert(value >= 0xfd, 'noncanonical compactsize');
        value
    } else if prefix == 0xfe {
        let value: u64 = read_u32_le(raw, ref offset).into();
        assert(value > 0xffff, 'noncanonical compactsize');
        value
    } else {
        let value = read_u64_le(raw, ref offset);
        assert(value > 0xffffffff, 'noncanonical compactsize');
        value
    }
}

fn read_exact(raw: @ByteArray, ref offset: usize, length: usize) -> ByteArray {
    ensure_available(raw, offset, length);
    let value = slice(raw, offset, length);
    offset += length;
    value
}

fn slice(raw: @ByteArray, start: usize, length: usize) -> ByteArray {
    ensure_available(raw, start, length);
    let mut value: ByteArray = "";
    let mut index: usize = 0;
    while index < length {
        value.append_byte(raw[start + index]);
        index += 1;
    }
    value
}
