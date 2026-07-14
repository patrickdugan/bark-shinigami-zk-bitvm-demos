use garaga::definitions::SECP256K1;
use garaga::signatures::schnorr::{SchnorrSignatureWithHint, is_valid_schnorr_signature};
use shinigami_engine::hash_tag::{HashTag, tagged_hash};

/// Bind a Garaga MSM witness to the exact BIP340 signature, x-only public key,
/// and Shinigami-computed message digest before invoking pure-Cairo secp256k1.
pub fn verify_bound_schnorr(
    witness: SchnorrSignatureWithHint,
    signature_bytes: @ByteArray,
    public_key_bytes: @ByteArray,
    message_hash: u256,
) {
    assert(signature_bytes.len() == 64, 'signature byte length');
    assert(public_key_bytes.len() == 32, 'public key byte length');
    let expected_rx = bytes_to_u256(signature_bytes, 0, 32);
    let expected_s = bytes_to_u256(signature_bytes, 32, 32);
    let expected_px = bytes_to_u256(public_key_bytes, 0, 32);

    let witness_rx: u256 = witness.signature.rx.try_into().expect('rx is u256');
    let witness_px: u256 = witness.signature.px.try_into().expect('px is u256');
    assert(witness_rx == expected_rx, 'signature rx not bound');
    assert(witness.signature.s == expected_s, 'signature s not bound');
    assert(witness_px == expected_px, 'public key not bound');

    let mut challenge_message: ByteArray = "";
    challenge_message.append_word(expected_rx.high.into(), 16);
    challenge_message.append_word(expected_rx.low.into(), 16);
    challenge_message.append_word(expected_px.high.into(), 16);
    challenge_message.append_word(expected_px.low.into(), 16);
    challenge_message.append_word(message_hash.high.into(), 16);
    challenge_message.append_word(message_hash.low.into(), 16);
    let challenge = tagged_hash(HashTag::Bip0340Challenge, @challenge_message) % SECP256K1.n;
    assert(witness.signature.e == challenge, 'BIP340 challenge mismatch');
    assert(is_valid_schnorr_signature(witness, 2), 'BIP340 signature invalid');
}

fn bytes_to_u256(bytes: @ByteArray, start: usize, length: usize) -> u256 {
    assert(length == 32, 'u256 byte length');
    assert(start <= bytes.len() && length <= bytes.len() - start, 'u256 bytes truncated');
    let mut value: u256 = 0;
    let mut index: usize = 0;
    while index < length {
        value *= 0x100;
        value += bytes[start + index].into();
        index += 1;
    }
    value
}
