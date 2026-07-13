#!/usr/bin/env node

/*
 * Executable red-team probes for the showcase threat boundary.
 *
 * A successful run means the attacks still reproduce. That is intentional:
 * callers can use the non-zero exit status to notice when a primitive or
 * fixture changes enough that these probes no longer demonstrate the stated
 * weaknesses.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const CAIRO_PRIME = (1n << 251n) + (17n << 192n) + 1n;
const U128_MAX = (1n << 128n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const U32_MAX = (1n << 32n) - 1n;

const FIXTURES = [
	{
		id: 'generic-owner-exit',
		file: 'owner_csv_exit.input.json',
		inputSha256: '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b',
		binding: '0x4d4226614ba0e3cf8e3061925ddcc0f4ee8d463a5a',
		amount: 100000n,
		delay: 144n,
		amountDelayCollisionSha256: '12a3ebe69221663259e2a064633b45049802a10a3a728e43eb6cb7edb5c22914',
		settlementLimbCollisionSha256: '53a368faa1b7e7bc39a85fdbe888522c3dec6f9dc361f99608c9defaad56dda3'
	},
	{
		id: 'bark-native-owner-exit',
		file: 'bark_pubkey_vtxo_owner_exit.input.json',
		inputSha256: '565c91be50cde7cb99c08acb9c1120ec99b3a68bd1277a723fc56663abfda273',
		binding: '0x2fbef1d3496f428d84f5031c8619cd7c8136d3c',
		amount: 10000n,
		delay: 2016n,
		amountDelayCollisionSha256: '7b8494c262ed23a93ada5ca8eea81d81b992d0742fc737c42e623c108290f334',
		settlementLimbCollisionSha256: 'f515d7e48d15da80230055c9fe93725560f4b9cd024ae6866b02d54ec22ada60'
	}
];

const OPERATOR_SECRET = 0x12345n;
const CHALLENGER_SECRET = 0x67890n;
const RECOVERY_SPK = `0014${'09'.repeat(20)}`;
const CHALLENGE_SPK = `0014${'08'.repeat(20)}`;

function sha256(value) {
	return crypto.createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
	return sha256(value).toString('hex');
}

function canonicalCairoJson(fields) {
	if (!Array.isArray(fields) || fields.length !== 25) {
		throw new Error('a Cairo claim must contain exactly 25 fields');
	}
	return `[\n${fields.map((field) => `  "${field}"`).join(',\n')}\n]\n`;
}

function felt(value) {
	return BigInt(String(value));
}

function modPrime(value) {
	const reduced = value % CAIRO_PRIME;
	return reduced < 0n ? reduced + CAIRO_PRIME : reduced;
}

function mix(left, right) {
	return modPrime((31n * left) + (17n * right) + 7n);
}

function mixHashLimbs(high, low) {
	return mix(high, low);
}

function computeLinearBinding(fields) {
	const manifestId = mixHashLimbs(felt(fields[0]), felt(fields[1]));
	const taprootRoot = mixHashLimbs(felt(fields[2]), felt(fields[3]));
	const selectedLeaf = mixHashLimbs(felt(fields[4]), felt(fields[5]));
	const pathCommitment = mixHashLimbs(felt(fields[7]), felt(fields[8]));
	const settlementHash = mixHashLimbs(felt(fields[20]), felt(fields[21]));
	const policyPair = mix(manifestId, taprootRoot);
	const pathPair = mix(pathCommitment, felt(fields[9]));
	const leafPair = mix(selectedLeaf, felt(fields[6]));
	const policyPath = mix(policyPair, pathPair);
	const policyLeaf = mix(policyPath, leafPair);
	const settlementAmount = mix(settlementHash, felt(fields[22]));
	const settlementDelay = mix(settlementAmount, felt(fields[23]));
	return mix(policyLeaf, settlementDelay);
}

function cairoHex(value) {
	return `0x${value.toString(16)}`;
}

function changedIndexes(left, right) {
	const changed = [];
	for (let index = 0; index < left.length; index += 1) {
		if (left[index] !== right[index]) changed.push(index);
	}
	return changed;
}

function loadFixture(spec) {
	const fixturePath = path.join(__dirname, 'fixtures', spec.file);
	const fields = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
	const canonical = canonicalCairoJson(fields);
	const inputSha256 = sha256Hex(canonical);
	if (inputSha256 !== spec.inputSha256) {
		throw new Error(`${spec.id} fixture hash changed: ${inputSha256}`);
	}
	if (fields[24] !== spec.binding) {
		throw new Error(`${spec.id} fixture binding changed: ${fields[24]}`);
	}
	if (felt(fields[22]) !== spec.amount || felt(fields[23]) !== spec.delay) {
		throw new Error(`${spec.id} fixture amount or delay changed`);
	}
	if (computeLinearBinding(fields) !== felt(fields[24])) {
		throw new Error(`${spec.id} fixture does not satisfy the documented linear binding`);
	}
	return { fixturePath, fields, inputSha256 };
}

function requireCollision(condition, message) {
	if (!condition) throw new Error(message);
}

function reproduceAmountDelayCollision(spec, original) {
	const collided = [...original.fields];
	const amount = felt(collided[22]);
	const delay = felt(collided[23]);
	const nextAmount = amount + 1n;
	const nextDelay = delay - 31n;
	const originalBinding = computeLinearBinding(original.fields);

	requireCollision(nextAmount > 0n && nextAmount <= U64_MAX, `${spec.id} collided amount is out of u64 range`);
	requireCollision(nextDelay > 0n && nextDelay <= U32_MAX, `${spec.id} collided delay is out of u32 range`);
	collided[22] = cairoHex(nextAmount);
	collided[23] = cairoHex(nextDelay);

	const collisionBinding = computeLinearBinding(collided);
	const collisionSha256 = sha256Hex(canonicalCairoJson(collided));
	requireCollision(collisionBinding === originalBinding, `${spec.id} amount/delay collision stopped colliding`);
	requireCollision(collisionBinding === felt(collided[24]), `${spec.id} amount/delay collision fails the Cairo binding check`);
	requireCollision(collisionSha256 !== original.inputSha256, `${spec.id} amount/delay collision did not change the claim`);
	requireCollision(collisionSha256 === spec.amountDelayCollisionSha256, `${spec.id} amount/delay collision vector changed`);
	requireCollision(
		JSON.stringify(changedIndexes(original.fields, collided)) === JSON.stringify([22, 23]),
		`${spec.id} amount/delay collision changed unexpected fields`
	);

	return {
		fixture: spec.id,
		family: 'amount-plus-one_delay-minus-thirty-one',
		changed_field_indexes: [22, 23],
		original: { amount_sats: amount.toString(), exit_delay: delay.toString(), input_sha256: original.inputSha256 },
		collision: { amount_sats: nextAmount.toString(), exit_delay: nextDelay.toString(), input_sha256: collisionSha256 },
		binding_commitment: cairoHex(originalBinding),
		binding_unchanged: true,
		claim_changed: true,
		cairo_binding_check_still_passes: true
	};
}

function reproduceSettlementLimbCollision(spec, original) {
	const collided = [...original.fields];
	const high = felt(collided[20]);
	const low = felt(collided[21]);
	const nextHigh = high + 17n;
	const nextLow = low - 31n;
	const originalBinding = computeLinearBinding(original.fields);

	requireCollision(nextHigh >= 0n && nextHigh <= U128_MAX, `${spec.id} collided settlement high limb is out of u128 range`);
	requireCollision(nextLow >= 0n && nextLow <= U128_MAX, `${spec.id} collided settlement low limb is out of u128 range`);
	collided[20] = cairoHex(nextHigh);
	collided[21] = cairoHex(nextLow);

	const collisionBinding = computeLinearBinding(collided);
	const collisionSha256 = sha256Hex(canonicalCairoJson(collided));
	requireCollision(collisionBinding === originalBinding, `${spec.id} settlement-limb collision stopped colliding`);
	requireCollision(collisionBinding === felt(collided[24]), `${spec.id} settlement-limb collision fails the Cairo binding check`);
	requireCollision(collisionSha256 !== original.inputSha256, `${spec.id} settlement-limb collision did not change the claim`);
	requireCollision(collisionSha256 === spec.settlementLimbCollisionSha256, `${spec.id} settlement-limb collision vector changed`);
	requireCollision(
		JSON.stringify(changedIndexes(original.fields, collided)) === JSON.stringify([20, 21]),
		`${spec.id} settlement-limb collision changed unexpected fields`
	);

	return {
		fixture: spec.id,
		family: 'settlement-high-plus-seventeen_low-minus-thirty-one',
		changed_field_indexes: [20, 21],
		original: { high_limb: cairoHex(high), low_limb: cairoHex(low), input_sha256: original.inputSha256 },
		collision: { high_limb: cairoHex(nextHigh), low_limb: cairoHex(nextLow), input_sha256: collisionSha256 },
		binding_commitment: cairoHex(originalBinding),
		binding_unchanged: true,
		claim_changed: true,
		cairo_binding_check_still_passes: true
	};
}

function deterministicRandom(seed) {
	let counter = 0;
	return (size) => {
		if (size !== 32) throw new Error(`unexpected deterministic RNG request: ${size}`);
		counter += 1;
		return sha256(Buffer.from(`${seed}:${counter}`, 'utf8'));
	};
}

function deterministicEd25519KeyPair(seedLabel) {
	const seed = sha256(Buffer.from(seedLabel, 'utf8'));
	const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
	const privateKey = crypto.createPrivateKey({
		key: Buffer.concat([pkcs8Prefix, seed]),
		format: 'der',
		type: 'pkcs8'
	});
	return { privateKey, publicKey: crypto.createPublicKey(privateKey) };
}

function requireUtxoRefApis(repo) {
	const referee = path.join(path.resolve(repo), 'bitvm3', 'utxo_referee');
	const required = [
		'utxoref_v2.js',
		'bitvm_trace_v2.js',
		'bitvm_assertion_graph_v2.js',
		'tradelayer_dlc_adaptor_sig.js'
	];
	for (const file of required) {
		if (!fs.existsSync(path.join(referee, file))) {
			throw new Error(`missing UTXORef module: ${path.join(referee, file)}`);
		}
	}
	return {
		utxoref: require(path.join(referee, 'utxoref_v2.js')),
		trace: require(path.join(referee, 'bitvm_trace_v2.js')),
		assertion: require(path.join(referee, 'bitvm_assertion_graph_v2.js')),
		adaptor: require(path.join(referee, 'tradelayer_dlc_adaptor_sig.js'))
	};
}

function reproduceFalseAllOnesGraph(apis, barkFixture) {
	const { publicKey, privateKey } = deterministicEd25519KeyPair('bark-bitvm-red-team-self-signer-v1');
	const keyId = apis.utxoref.publicKeyId(publicKey);
	const externalFacts = {
		claim_binding_matches: false,
		pinned_stwo_statement_verified: false,
		shinigami_engine_check_verified: false
	};
	const contractId = barkFixture.inputSha256;
	const stateEnvelope = apis.utxoref.buildSignedStateCheckpointV2({
		network: 'bitcoin-regtest',
		chainGenesisHash: '00'.repeat(32),
		contractId,
		epochId: '1',
		snapshotHeight: 1000,
		snapshotBlockHash: sha256Hex('red-team-snapshot'),
		marks: {
			externalEvidence: {
				...externalFacts,
				note: 'signed false facts; the public trace dishonestly reveals all ones'
			}
		},
		settlementAddressMap: {
			A: { address: 'red-team-beneficiary-a', scriptPubKeyHex: `0014${'01'.repeat(20)}` },
			C: { address: 'red-team-beneficiary-c', scriptPubKeyHex: `0014${'03'.repeat(20)}` }
		},
		pnlRows: [
			{
				id: 'red-team-a-wins', contractId, side: 'long', entryPrice: 2100,
				closePrice: 2200, quantityUnits: 30, collateralSats: 50000,
				traderAddress: 'A', counterpartyAddress: 'B'
			},
			{
				id: 'red-team-c-wins', contractId, side: 'long', entryPrice: 2100,
				closePrice: 2200, quantityUnits: 20, collateralSats: 50000,
				traderAddress: 'C', counterpartyAddress: 'B'
			}
		]
	}, { privateKey, publicKey });
	const stateVerification = {
		trustedSigners: { [keyId]: publicKey },
		expectedNetwork: 'bitcoin-regtest',
		expectedGenesisHash: '00'.repeat(32),
		currentHeight: 1002
	};
	const stateCheck = apis.utxoref.verifySignedStateCheckpointV2(stateEnvelope, stateVerification);
	if (!stateCheck.ok) throw new Error(`self-signed checkpoint did not verify: ${stateCheck.reason}`);

	const binding = apis.assertion.buildSettlementTraceBindingV2({ stateEnvelope, feeSats: '1000' });
	const labels = [
		'claim_binding_matches',
		'pinned_stwo_statement_verified',
		'proof_bound',
		'shinigami_engine_check_verified',
		'authorization_assertion'
	];
	const wireBundle = apis.trace.buildWireSecretSetV2(labels, {
		randomBytes: deterministicRandom('bark-bitvm-red-team-all-ones-v1')
	});
	const values = Object.fromEntries(labels.map((label) => [label, 1]));
	const publicTrace = apis.trace.buildPublicTraceV2({
		circuitId: 'bark-shinigami-pinned-external-assertions-v2',
		binding,
		gates: [
			{
				type: 'and',
				inputs: ['claim_binding_matches', 'pinned_stwo_statement_verified'],
				output: 'proof_bound'
			},
			{
				type: 'and',
				inputs: ['proof_bound', 'shinigami_engine_check_verified'],
				output: 'authorization_assertion'
			}
		],
		wireBundle,
		values
	});
	const traceCheck = apis.trace.verifyPublicTraceV2(publicTrace);
	if (!traceCheck.ok) throw new Error(`dishonest all-ones trace did not verify: ${traceCheck.reason}`);

	const operatorXonly = apis.adaptor.xOnlyPubkey(OPERATOR_SECRET).toString('hex');
	const challengerXonly = apis.adaptor.xOnlyPubkey(CHALLENGER_SECRET).toString('hex');
	const template = apis.assertion.buildBitvmAssertionTemplateV2({
		network: 'bitcoin-regtest',
		publicTrace,
		expectedInputs: {
			claim_binding_matches: 1,
			pinned_stwo_statement_verified: 1,
			shinigami_engine_check_verified: 1
		},
		operatorXonly,
		challengerXonly,
		challengeCsvBlocks: 6,
		recoveryCsvBlocks: 144
	});
	const graph = apis.assertion.finalizeBitvmAssertionGraphV2({
		template,
		publicTrace,
		stateEnvelope,
		stateVerification,
		assertionOutpoint: {
			txid: sha256Hex(`red-team-assertion:${contractId}`),
			vout: 0,
			amountSats: binding.assertionAmountSats,
			scriptPubKeyHex: template.p2trScriptPubKey
		},
		feeSats: binding.feeSats,
		recoveryFeeSats: '500',
		recoveryScriptPubKeyHex: RECOVERY_SPK,
		operatorSecret: OPERATOR_SECRET,
		challengerSecret: CHALLENGER_SECRET,
		operatorAux: Buffer.alloc(32, 1),
		challengerAux: Buffer.alloc(32, 2),
		recoveryAux: Buffer.alloc(32, 3)
	});
	const graphCheck = apis.assertion.verifyBitvmAssertionGraphV2(graph, stateVerification);
	if (!graphCheck.ok) throw new Error(`dishonest all-ones graph did not verify: ${graphCheck.reason}`);

	let disproveConstructible = true;
	let disproveError = null;
	try {
		apis.assertion.buildBitvmDisproveV2(graph, {
			stateVerification,
			challengerSecret: CHALLENGER_SECRET,
			challengerAux: Buffer.alloc(32, 4),
			feeSats: '400',
			challengeScriptPubKeyHex: CHALLENGE_SPK
		});
	} catch (error) {
		disproveConstructible = false;
		disproveError = error.message;
	}

	if (graphCheck.fraudCount !== 0) throw new Error(`dishonest all-ones graph now reports ${graphCheck.fraudCount} frauds`);
	if (disproveConstructible) throw new Error('dishonest all-ones graph unexpectedly produced a disprove');
	if (!/no constructible fraud proof/i.test(disproveError || '')) {
		throw new Error(`dishonest all-ones disprove failed for an unexpected reason: ${disproveError}`);
	}
	if (!graph.settlementPath.witnessTxHex) throw new Error('dishonest all-ones graph omitted its co-signed settlement witness');

	return {
		attack: 'signed-false-facts_all-ones-public-trace',
		external_facts_committed_in_signed_checkpoint: externalFacts,
		operator_disclosed_trace_values: values,
		self_selected_checkpoint_signer_verified: stateCheck.ok,
		public_trace_verified: traceCheck.ok,
		graph_verified: graphCheck.ok,
		fraud_count: graphCheck.fraudCount,
		disprove_constructible: disproveConstructible,
		disprove_error: disproveError,
		co_signed_settlement_witness_ready: true,
		operator_controls_demo_challenger: true,
		graph_hash: graph.graphHash,
		reproduced: true
	};
}

function parseArgs(argv) {
	const args = {};
	for (let index = 0; index < argv.length; index += 2) {
		const key = argv[index];
		const value = argv[index + 1];
		if (!key || !key.startsWith('--') || value === undefined) {
			throw new Error('usage: node red-team-attacks.js --utxoref-repo PATH');
		}
		args[key.slice(2)] = value;
	}
	if (!args['utxoref-repo']) throw new Error('missing --utxoref-repo');
	return args;
}

function run() {
	const args = parseArgs(process.argv.slice(2));
	const loadedFixtures = new Map(FIXTURES.map((spec) => [spec.id, loadFixture(spec)]));
	const collisions = [];
	for (const spec of FIXTURES) {
		const original = loadedFixtures.get(spec.id);
		collisions.push(reproduceAmountDelayCollision(spec, original));
		collisions.push(reproduceSettlementLimbCollision(spec, original));
	}
	const allOnes = reproduceFalseAllOnesGraph(
		requireUtxoRefApis(args['utxoref-repo']),
		loadedFixtures.get('bark-native-owner-exit')
	);
	return {
		schema: 'bark-bitvm-red-team-attacks-v1',
		all_attacks_reproduced: true,
		expected_process_exit: 0,
		threat_boundary: 'UTXORef verifies disclosed-bit consistency; it does not observe STWO, Shinigami, or Bark truth.',
		attacks: {
			false_all_ones_graph: allOnes,
			linear_binding_collisions: collisions
		}
	};
}

let report;
try {
	report = run();
} catch (error) {
	report = {
		schema: 'bark-bitvm-red-team-attacks-v1',
		all_attacks_reproduced: false,
		expected_process_exit: 1,
		error: error.message
	};
	process.exitCode = 1;
}

process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
