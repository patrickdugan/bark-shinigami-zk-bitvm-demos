use std::env;
use std::fs;
use std::path::Path;

use anyhow::{ensure, Context, Result};
use risc0_zkvm::{compute_image_id, default_executor, ExecutorEnv, ExitCode};

const EVIDENCE_LEN: usize = 184;
const PROGRAM_HASH: &str = "00bcd09f617edcfc9ee2bbbb74192f42dfed6b7a505578a3748ac93f8ad697f0";
const PROGRAM_COMMITMENT: &str = "4c75023ef37407be739a93eab0f17ff624ba716e07efab796af59846714ef067";
const POLICY_COMMITMENT: &str = "626cd38f63851c1067c7ee1594ae880694255346c0a179d68c0bfff571955314";

fn main() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let elf_path = args
        .next()
        .context("usage: executor ELF PROOF EXPECTED_STATEMENT EXPECTED_SIGHASH")?;
    let proof_path = args.next().context("missing proof path")?;
    let expected_statement = args
        .next()
        .context("missing expected 32-byte statement digest")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("statement digest must be UTF-8"))?;
    let expected_sighash = args
        .next()
        .context("missing expected 32-byte Taproot sighash")?
        .into_string()
        .map_err(|_| anyhow::anyhow!("Taproot sighash must be UTF-8"))?;
    ensure!(args.next().is_none(), "unexpected trailing argument");
    validate_hex_digest(&expected_statement, "statement digest")?;
    validate_hex_digest(&expected_sighash, "Taproot sighash")?;

    let elf = fs::read(&elf_path).with_context(|| format!("read ELF {:?}", elf_path))?;
    let proof = fs::read(&proof_path).with_context(|| format!("read proof {:?}", proof_path))?;
    let env = ExecutorEnv::builder().write(&proof)?.build()?;
    let session = default_executor().execute(env, &elf)?;
    ensure!(
        session.exit_code == ExitCode::Halted(0),
        "guest did not halt cleanly"
    );

    let journal = &session.journal.bytes;
    ensure!(
        journal.len() == EVIDENCE_LEN,
        "expected a denial-evidence journal, got {} bytes",
        journal.len()
    );
    ensure!(&journal[0..8] == b"BARKZKVE", "wrong evidence domain");
    ensure!(read_u32(&journal[8..12]) == 1, "wrong evidence version");
    ensure!(
        read_u32(&journal[12..16]) == 1,
        "transaction relation was not proven"
    );
    ensure!(
        read_u32(&journal[16..20]) == 0,
        "fixture unexpectedly proved chain state"
    );
    ensure!(
        read_u32(&journal[20..24]) == 0,
        "fixture unexpectedly authorized an operator take"
    );
    ensure!(
        encode_hex(&journal[24..56]) == PROGRAM_HASH,
        "wrong STWO program hash"
    );
    ensure!(
        encode_hex(&journal[56..88]) == PROGRAM_COMMITMENT,
        "wrong program commitment"
    );
    ensure!(
        encode_hex(&journal[88..120]) == POLICY_COMMITMENT,
        "wrong STWO policy commitment"
    );
    ensure!(
        encode_hex(&journal[120..152]) == expected_statement,
        "wrong statement digest"
    );
    ensure!(
        encode_hex(&journal[152..184]) == expected_sighash,
        "wrong Taproot sighash"
    );
    ensure!(
        journal.len() != 32,
        "denial evidence aliased the authorization journal"
    );

    let image_id = compute_image_id(&elf)?;
    let case = Path::new(&proof_path)
        .file_name()
        .and_then(|name| name.to_str())
        .context("proof path has no UTF-8 filename")?;
    let max_po2 = session
        .segments
        .iter()
        .map(|segment| segment.po2)
        .max()
        .unwrap_or(0);
    println!(
        "{{\"schema\":\"BarkRisc0ExecutionV1\",\"case\":\"{case}\",\"image_id\":\"{image_id}\",\"cycles\":{},\"segments\":{},\"max_po2\":{max_po2},\"journal_len\":{},\"transaction_relation_valid\":true,\"chain_state_verified\":false,\"operator_take_authorized\":false,\"statement_digest\":\"{}\",\"taproot_sighash\":\"{}\"}}",
        session.cycles(),
        session.segments.len(),
        journal.len(),
        encode_hex(&journal[120..152]),
        encode_hex(&journal[152..184]),
    );
    Ok(())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("fixed four-byte field"))
}

fn validate_hex_digest(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{field} must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
