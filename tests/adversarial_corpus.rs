use std::collections::HashSet;

use ark::bitcoin::hashes::{sha256, Hash};
use bark_shinigami::v1::{
    ClaimHash, ClaimRole, ManifestBindingClaim, TaprootPath, TaprootSibling,
    CAIRO_INPUT_FIELD_COUNT,
};

const OWNER_EXIT_ALLOW: &str = include_str!("../fixtures/owner_csv_exit.input.json");
const OWNER_EXIT_CHALLENGE: &str =
    include_str!("../fixtures/bark_pubkey_vtxo_owner_exit.input.json");
const VIRTUAL_CET_GUARD: &str = include_str!("../fixtures/dlc_virtual_cet_settlement.input.json");
const MUTATIONS_PER_DEMO: usize = 10_000;

#[derive(Clone, Copy)]
struct CorpusCase {
    name: &'static str,
    fixture: &'static str,
    seed: u64,
}

const CASES: [CorpusCase; 3] = [
    CorpusCase {
        name: "owner_exit_allow",
        fixture: OWNER_EXIT_ALLOW,
        seed: 0x7a4a_14f9_c6d3_01a1,
    },
    CorpusCase {
        name: "owner_exit_challenge",
        fixture: OWNER_EXIT_CHALLENGE,
        seed: 0x5e11_0b8d_82c9_4723,
    },
    CorpusCase {
        name: "virtual_cet_guard",
        fixture: VIRTUAL_CET_GUARD,
        seed: 0xd1c0_5e77_9b24_6a41,
    },
];

/// Small deterministic generator used only to make the mutation corpus exactly
/// reproducible. It is not used for keys or any other cryptographic material.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }
}

fn fixture_fields(fixture: &str) -> [String; CAIRO_INPUT_FIELD_COUNT] {
    serde_json::from_str::<Vec<String>>(fixture)
        .expect("fixture is JSON")
        .try_into()
        .expect("fixture has exactly 25 fields")
}

fn parse_hex_u128(value: &str) -> Result<u128, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| "missing lowercase 0x prefix".to_owned())?;
    if digits.is_empty() {
        return Err("empty Cairo integer".to_owned());
    }
    u128::from_str_radix(digits, 16).map_err(|error| error.to_string())
}

fn parse_hash(
    fields: &[String; CAIRO_INPUT_FIELD_COUNT],
    index: usize,
) -> Result<ClaimHash, String> {
    let low_index = index
        .checked_add(1)
        .ok_or_else(|| "hash limb offset overflow".to_owned())?;
    Ok(ClaimHash::from_u128_limbs(
        parse_hex_u128(&fields[index])?,
        parse_hex_u128(&fields[low_index])?,
    ))
}

/// Parse the semantic claim and re-encode it through the Bark adapter. Equality
/// with the supplied array therefore checks the role/depth/range rules, inactive
/// path padding, path fold, binding commitment, and canonical integer spelling.
fn reencode(fields: &[String; CAIRO_INPUT_FIELD_COUNT]) -> Result<[String; 25], String> {
    let depth = usize::try_from(parse_hex_u128(&fields[10])?).map_err(|error| error.to_string())?;
    let mut siblings = Vec::with_capacity(depth.min(4));
    for index in 0..depth {
        let offset = index
            .checked_mul(3)
            .and_then(|value| value.checked_add(11))
            .ok_or_else(|| "path offset overflow".to_owned())?;
        if offset.checked_add(2).is_none_or(|last| last >= 20) {
            return Err("path exceeds the fixed three-sibling ABI".to_owned());
        }
        let side = u8::try_from(parse_hex_u128(&fields[offset + 2])?)
            .map_err(|error| error.to_string())?;
        siblings.push(
            TaprootSibling::from_side_code(parse_hash(fields, offset)?, side)
                .map_err(|error| error.to_string())?,
        );
    }

    let role = u8::try_from(parse_hex_u128(&fields[6])?).map_err(|error| error.to_string())?;
    let amount = u64::try_from(parse_hex_u128(&fields[22])?).map_err(|error| error.to_string())?;
    let delay = u32::try_from(parse_hex_u128(&fields[23])?).map_err(|error| error.to_string())?;
    let claim = ManifestBindingClaim::from_manifest_fields(
        parse_hash(fields, 0)?,
        parse_hash(fields, 2)?,
        parse_hash(fields, 4)?,
        ClaimRole::try_from(role).map_err(|error| error.to_string())?,
        parse_hash(fields, 7)?,
        TaprootPath::new(&siblings).map_err(|error| error.to_string())?,
        parse_hash(fields, 20)?,
        amount,
        delay,
    )
    .map_err(|error| error.to_string())?;
    Ok(claim.to_cairo_input().to_cairo_args())
}

fn cairo_hex(value: u128) -> String {
    format!("0x{value:x}")
}

fn different_u128(original: &str, rng: &mut SplitMix64) -> String {
    let original = parse_hex_u128(original).expect("fixture integer fits u128");
    let mut replacement = (u128::from(rng.next()) << 64) | u128::from(rng.next());
    if replacement == original {
        replacement ^= 1;
    }
    cairo_hex(replacement)
}

fn different_u64(original: &str, rng: &mut SplitMix64, nonzero: bool) -> String {
    let original = u64::try_from(parse_hex_u128(original).expect("fixture integer"))
        .expect("fixture integer fits u64");
    let mut replacement = rng.next();
    if nonzero && replacement == 0 {
        replacement = 1;
    }
    if replacement == original {
        let minimum = if nonzero { 1 } else { 0 };
        replacement = replacement.wrapping_add(1).max(minimum);
    }
    format!("0x{replacement:x}")
}

fn different_u32(original: &str, rng: &mut SplitMix64, nonzero: bool) -> String {
    let original = u32::try_from(parse_hex_u128(original).expect("fixture integer"))
        .expect("fixture integer fits u32");
    let mut replacement = rng.next() as u32;
    if nonzero && replacement == 0 {
        replacement = 1;
    }
    if replacement == original {
        let minimum = if nonzero { 1 } else { 0 };
        replacement = replacement.wrapping_add(1).max(minimum);
    }
    format!("0x{replacement:x}")
}

fn different_u8(original: &str, rng: &mut SplitMix64) -> String {
    let original = u8::try_from(parse_hex_u128(original).expect("fixture integer"))
        .expect("fixture integer fits u8");
    let mut replacement = rng.next() as u8;
    if replacement == original {
        replacement = replacement.wrapping_add(1);
    }
    format!("0x{replacement:x}")
}

fn different_felt(original: &str, rng: &mut SplitMix64) -> String {
    let mut limbs = [rng.next(), rng.next(), rng.next(), rng.next()];
    // Keep the value below 2^248, which is always inside the Cairo field.
    limbs[0] &= 0x00ff_ffff_ffff_ffff;
    let mut replacement = format!(
        "0x{:x}{:016x}{:016x}{:016x}",
        limbs[0], limbs[1], limbs[2], limbs[3]
    );
    if replacement == original {
        replacement.push('1');
    }
    replacement
}

fn mutate_one_field(
    original: &[String; CAIRO_INPUT_FIELD_COUNT],
    field: usize,
    rng: &mut SplitMix64,
) -> [String; CAIRO_INPUT_FIELD_COUNT] {
    let mut mutated = original.clone();
    mutated[field] = match field {
        0..=5 | 7..=8 | 11..=12 | 14..=15 | 17..=18 | 20..=21 => {
            different_u128(&original[field], rng)
        }
        6 | 13 | 16 | 19 => different_u8(&original[field], rng),
        9 | 24 => different_felt(&original[field], rng),
        10 => different_u32(&original[field], rng, false),
        22 => different_u64(&original[field], rng, true),
        23 => different_u32(&original[field], rng, true),
        _ => unreachable!("the ABI contains exactly 25 fields"),
    };
    assert_ne!(mutated[field], original[field]);
    mutated
}

fn canonical_json(fields: &[String; CAIRO_INPUT_FIELD_COUNT]) -> String {
    let lines = fields
        .iter()
        .map(|field| format!("  \"{field}\""))
        .collect::<Vec<_>>();
    format!("[\n{}\n]\n", lines.join(",\n"))
}

fn claim_input_digest(fields: &[String; CAIRO_INPUT_FIELD_COUNT]) -> sha256::Hash {
    // This is deliberately scoped to the existing 25-field Cairo input. The
    // production StatementV1 digest must instead hash its canonical binary Bark
    // spend envelope and must not reuse this JSON compatibility digest.
    sha256::Hash::hash(canonical_json(fields).as_bytes())
}

#[test]
fn ten_thousand_seeded_single_field_mutations_per_demo_are_detected_by_reencoding() {
    for case in CASES {
        let original = fixture_fields(case.fixture);
        assert_eq!(reencode(&original).expect("fixture re-encodes"), original);

        let mut rng = SplitMix64(case.seed);
        let mut field_hits = [0usize; CAIRO_INPUT_FIELD_COUNT];
        let mut distinct_statements = HashSet::new();
        for mutation_index in 0..MUTATIONS_PER_DEMO {
            let field = mutation_index % CAIRO_INPUT_FIELD_COUNT;
            field_hits[field] += 1;
            let mutated = mutate_one_field(&original, field, &mut rng);
            distinct_statements.insert(claim_input_digest(&mutated));

            let rejected = match reencode(&mutated) {
                Ok(reencoded) => reencoded != mutated,
                Err(_) => true,
            };
            assert!(
                rejected,
                "{} mutation {mutation_index} of field {field} unexpectedly survived",
                case.name
            );
        }

        assert!(field_hits.iter().all(|hits| *hits >= 400));
        assert!(
            distinct_statements.len() >= 9_000,
            "{} corpus had only {} distinct statements",
            case.name,
            distinct_statements.len()
        );
    }
}

#[test]
fn known_linear_collisions_require_the_full_cairo_claim_digest() {
    for case in CASES {
        let original = fixture_fields(case.fixture);
        let original_digest = claim_input_digest(&original);

        let mut amount_delay = original.clone();
        let amount = parse_hex_u128(&amount_delay[22]).expect("amount");
        let delay = parse_hex_u128(&amount_delay[23]).expect("delay");
        assert!(
            delay > 31,
            "{} fixture needs room for the collision",
            case.name
        );
        amount_delay[22] = cairo_hex(amount + 1);
        amount_delay[23] = cairo_hex(delay - 31);
        assert_eq!(
            reencode(&amount_delay).expect("colliding claim remains valid"),
            amount_delay,
            "{} amount/delay pair stopped colliding",
            case.name
        );
        assert_ne!(claim_input_digest(&amount_delay), original_digest);

        let mut settlement_limbs = original.clone();
        let high = parse_hex_u128(&settlement_limbs[20]).expect("settlement high limb");
        let low = parse_hex_u128(&settlement_limbs[21]).expect("settlement low limb");
        assert!(
            high <= u128::MAX - 17 && low >= 31,
            "{} fixture needs room for the limb collision",
            case.name
        );
        settlement_limbs[20] = cairo_hex(high + 17);
        settlement_limbs[21] = cairo_hex(low - 31);
        assert_eq!(
            reencode(&settlement_limbs).expect("colliding claim remains valid"),
            settlement_limbs,
            "{} settlement limbs stopped colliding",
            case.name
        );
        assert_ne!(claim_input_digest(&settlement_limbs), original_digest);
    }
}

#[test]
fn inactive_path_padding_is_not_bound_by_the_legacy_cairo_claim() {
    let mut exercised = 0;
    for case in CASES {
        let original = fixture_fields(case.fixture);
        let depth = usize::try_from(parse_hex_u128(&original[10]).expect("path depth"))
            .expect("path depth fits usize");
        if depth == 3 {
            continue;
        }
        exercised += 1;

        let first_inactive_field = 11 + depth * 3;
        let mut padded = original.clone();
        padded[first_inactive_field] = "0x1".to_owned();

        // Bark's adapter restores canonical zero padding, while the legacy
        // Cairo source never reads an inactive slot. Its path fold and linear
        // public binding therefore remain the original values. The full input
        // digest is the only existing showcase check that distinguishes this
        // direct-Cairo-input substitution.
        assert_eq!(reencode(&padded).expect("claim still decodes"), original);
        assert_eq!(padded[9], original[9]);
        assert_eq!(padded[24], original[24]);
        assert_ne!(claim_input_digest(&padded), claim_input_digest(&original));
    }
    assert!(
        exercised > 0,
        "corpus no longer contains an inactive path slot"
    );
}

#[test]
fn proof_fixture_replay_is_distinct_across_all_demo_roles() {
    let digests: HashSet<_> = CASES
        .iter()
        .map(|case| claim_input_digest(&fixture_fields(case.fixture)))
        .collect();
    assert_eq!(digests.len(), CASES.len());
}
