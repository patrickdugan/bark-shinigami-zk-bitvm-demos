#!/usr/bin/env node

/*
 * Red/blue showcase for the trust boundary around external STWO/Shinigami facts.
 *
 * UTXORef V2 can disprove an operator who discloses a primary input as 0 when
 * the assertion template requires 1. It cannot discover that an internally
 * consistent, operator-disclosed 1 is false in the outside world. This harness
 * therefore fixes an independent challenger/cosigner key and policy before the
 * simulated funding decision. The key is held only inside createTrustedGate's
 * closure. A separately keyed test-double verifier hashes supplied synthetic
 * artifact bytes, derives the modeled facts, and signs the policy/case/nonce
 * context. The gate releases a UTXORef fast-settlement package only when that
 * attestation, the byte-derived hashes, and the operator disclosure all agree.
 *
 * This is a trusted-verifier admission/cosigning model. Bitcoin validates the
 * resulting BIP340 cosignature and Taproot transaction, not STWO or Shinigami.
 */

'use strict';

const assert = require('assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PINNED_UTXOREF_COMMIT = '13f43d7f7bbddf10fa507770645ef05e49189441';
const PINNED_UTXOREF_SOURCE_DIGEST = '3d3c65dd4f1f206357baf0aeea6aa1c0b85a5f2a2a6656ab04c120fe28450899';
const DEFAULT_UTXOREF_REPO = process.env.UTXOREF_REPO || 'C:\\projects\\UTXORef\\UTXO-Ref';
const POLICY_DOMAIN = 'bark-bitvm-showcase/trusted-cosigner-policy/v1';
const NETWORK = 'bitcoin-regtest';
const GENESIS_HASH = '00'.repeat(32);
const CIRCUIT_ID = 'bark-shinigami-trusted-cosigner-gate-v1';
const CHALLENGE_CSV_BLOCKS = 6;
const RECOVERY_CSV_BLOCKS = 144;
const RECOVERY_SPK = `0014${'09'.repeat(20)}`;
const CAIRO_PRIME = (1n << 251n) + (17n << 192n) + 1n;

const CLAIM_INPUT_SPECS = Object.freeze({
	'generic-owner-exit': Object.freeze({
		file: 'owner_csv_exit.input.json',
		sha256: '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b'
	}),
	'bark-native-owner-exit': Object.freeze({
		file: 'bark_pubkey_vtxo_owner_exit.input.json',
		sha256: '565c91be50cde7cb99c08acb9c1120ec99b3a68bd1277a723fc56663abfda273'
	})
});

// These are deliberately small synthetic byte artifacts. The independent
// verifier hashes the bytes it receives; callers never tell it which hashes to
// sign. Production must replace these test-double bytes with actual proof,
// executable, and Shinigami evidence loaded inside the isolated verifier.
const ARTIFACT_MATERIALS = deepFreeze({
	honest_generic: artifactMaterialFromUtf8(
		canonicalCairoJson(loadClaimInput('generic-owner-exit')),
		'bark-bitvm-test-double/stwo-proof/honest-generic/v1',
		'bark-bitvm-test-double/shinigami-check/csv-mature/v1'
	),
	false_stwo: artifactMaterialFromUtf8(
		canonicalCairoJson(loadClaimInput('generic-owner-exit')),
		'bark-bitvm-test-double/stwo-proof/invalid/v1',
		'bark-bitvm-test-double/shinigami-check/csv-mature/v1'
	),
	honest_bark_test_double: artifactMaterialFromUtf8(
		canonicalCairoJson(loadClaimInput('bark-native-owner-exit')),
		'bark-bitvm-test-double/stwo-proof/honest-bark/v1',
		'bark-bitvm-test-double/shinigami-check/csv-mature/v1'
	)
});

const ARTIFACT_BUNDLES = deepFreeze(Object.fromEntries(
	Object.entries(ARTIFACT_MATERIALS).map(([name, material]) => [
		name,
		deriveArtifactBundle(material)
	])
));

const FACT_KEYS = Object.freeze([
	'claim_binding_matches',
	'pinned_stwo_statement_verified',
	'shinigami_engine_check_verified'
]);

const GATES = Object.freeze([
	Object.freeze({
		type: 'and',
		inputs: Object.freeze(['claim_binding_matches', 'pinned_stwo_statement_verified']),
		output: 'proof_bound'
	}),
	Object.freeze({
		type: 'and',
		inputs: Object.freeze(['proof_bound', 'shinigami_engine_check_verified']),
		output: 'authorization_assertion'
	})
]);

const EXPECTED_INPUTS = Object.freeze({
	claim_binding_matches: 1,
	pinned_stwo_statement_verified: 1,
	shinigami_engine_check_verified: 1
});

const REQUIRED_UTXOREF_FILES = [
	'utxoref_v2.js',
	'bitvm_trace_v2.js',
	'bitvm_assertion_graph_v2.js',
	'tradelayer_dlc_adaptor_sig.js',
	'm1_spec.js',
	'tradelayer_bitvm_circuit.js',
	'tradelayer_taproot.js',
	'tradelayer_pnl_route_adapter.js',
	'tradelayer_pnl_state_netting.js',
	'tradelayer_taproot_script.js',
	'tradelayer_taproot_tree.js',
	'tradelayer_bitvm_dispute.js',
	'types.js',
	'm1_chain_env.js',
	'tradelayer_bitvm_gadgets.js',
	'merkle.js',
	'verify.js'
].map((name) => `bitvm3/utxo_referee/${name}`);

function canonicalStringify(value) {
	if (value === null || typeof value === 'boolean' || typeof value === 'number' ||
		typeof value === 'string') {
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
	if (typeof value === 'object') {
		return `{${Object.keys(value).sort().map((key) =>
			`${JSON.stringify(key)}:${canonicalStringify(value[key])}`).join(',')}}`;
	}
	throw new Error(`unsupported canonical value: ${typeof value}`);
}

function sha256Hex(value) {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function canonicalCairoJson(fields) {
	if (!Array.isArray(fields) || fields.length !== 25 ||
		fields.some((field) => typeof field !== 'string')) {
		throw new Error('claim input must contain exactly 25 Cairo strings');
	}
	return `[\n${fields.map((field) => `  ${JSON.stringify(field)}`).join(',\n')}\n]\n`;
}

function loadClaimInput(specId) {
	const spec = CLAIM_INPUT_SPECS[specId];
	if (!spec) throw new Error(`unknown pinned claim input: ${specId}`);
	const fields = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', spec.file), 'utf8'));
	const digest = sha256Hex(canonicalCairoJson(fields));
	if (digest !== spec.sha256) throw new Error(`${specId} canonical input digest changed: ${digest}`);
	return fields;
}

function modPrime(value) {
	const reduced = value % CAIRO_PRIME;
	return reduced < 0n ? reduced + CAIRO_PRIME : reduced;
}

function mix(left, right) {
	return modPrime((31n * left) + (17n * right) + 7n);
}

function computeLinearBinding(fields) {
	const value = (index) => BigInt(fields[index]);
	const hash = (index) => mix(value(index), value(index + 1));
	const policyPair = mix(hash(0), hash(2));
	const pathPair = mix(hash(7), value(9));
	const leafPair = mix(hash(4), value(6));
	const policyLeaf = mix(mix(mix(policyPair, pathPair), leafPair),
		mix(mix(hash(20), value(22)), value(23)));
	return policyLeaf;
}

function amountDelayCollision(fields) {
	const collision = [...fields];
	collision[22] = `0x${(BigInt(fields[22]) + 1n).toString(16)}`;
	collision[23] = `0x${(BigInt(fields[23]) - 31n).toString(16)}`;
	assert.equal(computeLinearBinding(collision), computeLinearBinding(fields));
	assert.notEqual(sha256Hex(canonicalCairoJson(collision)), sha256Hex(canonicalCairoJson(fields)));
	return collision;
}

function settlementLimbCollision(fields) {
	const collision = [...fields];
	collision[20] = `0x${(BigInt(fields[20]) + 17n).toString(16)}`;
	collision[21] = `0x${(BigInt(fields[21]) - 31n).toString(16)}`;
	assert.equal(computeLinearBinding(collision), computeLinearBinding(fields));
	assert.notEqual(sha256Hex(canonicalCairoJson(collision)), sha256Hex(canonicalCairoJson(fields)));
	return collision;
}

function taggedHash(tag, value) {
	return sha256Hex(Buffer.concat([
		Buffer.from(`${tag}\0`, 'utf8'),
		Buffer.from(canonicalStringify(value), 'utf8')
	]));
}

function cloneJson(value) {
	return JSON.parse(JSON.stringify(value));
}

function deepFreeze(value) {
	if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
	for (const nested of Object.values(value)) deepFreeze(nested);
	return Object.freeze(value);
}

function artifactMaterialFromUtf8(claimInput, proofArtifact, shinigamiArtifact) {
	return {
		kind: 'bark_bitvm_verifier_artifact_bytes_v1',
		claimInputBase64: Buffer.from(claimInput, 'utf8').toString('base64'),
		proofArtifactBase64: Buffer.from(proofArtifact, 'utf8').toString('base64'),
		shinigamiArtifactBase64: Buffer.from(shinigamiArtifact, 'utf8').toString('base64')
	};
}

function normalizeArtifactMaterial(value) {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error('artifact byte material must be an object');
	}
	const names = [
		'kind', 'claimInputBase64', 'proofArtifactBase64',
		'shinigamiArtifactBase64'
	];
	if (Object.keys(value).sort().join('|') !== [...names].sort().join('|')) {
		throw new Error('artifact byte material has an unexpected field');
	}
	if (value.kind !== 'bark_bitvm_verifier_artifact_bytes_v1') {
		throw new Error('wrong artifact byte material kind');
	}
	for (const name of names.slice(1)) {
		if (typeof value[name] !== 'string' || value[name].length === 0 ||
			Buffer.from(value[name], 'base64').toString('base64') !== value[name]) {
			throw new Error(`artifact byte material ${name} must be canonical non-empty base64`);
		}
	}
	return cloneJson(value);
}

function deriveArtifactBundle(materialInput) {
	const material = normalizeArtifactMaterial(materialInput);
	return {
		kind: 'bark_bitvm_verifier_artifacts_v1',
		claimInputSha256: sha256Hex(Buffer.from(material.claimInputBase64, 'base64')),
		proofArtifactSha256: sha256Hex(Buffer.from(material.proofArtifactBase64, 'base64')),
		shinigamiArtifactSha256: sha256Hex(
			Buffer.from(material.shinigamiArtifactBase64, 'base64')
		)
	};
}

function normalizeAttestationContext(value) {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error('verifier request context must be an object');
	}
	const names = ['policyHash', 'network', 'caseId', 'requestNonce'];
	if (Object.keys(value).sort().join('|') !== [...names].sort().join('|')) {
		throw new Error('verifier request context has an unexpected field');
	}
	for (const name of ['policyHash', 'requestNonce']) {
		if (typeof value[name] !== 'string' || !/^[0-9a-f]{64}$/.test(value[name])) {
			throw new Error(`verifier request context ${name} must be 32-byte lowercase hex`);
		}
	}
	for (const name of ['network', 'caseId']) {
		if (typeof value[name] !== 'string' || value[name].length === 0) {
			throw new Error(`verifier request context ${name} must be a non-empty string`);
		}
	}
	return cloneJson(value);
}

function normalizeArtifactBundle(value) {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error('artifact bundle must be an object');
	}
	const names = [
		'kind', 'claimInputSha256', 'proofArtifactSha256',
		'shinigamiArtifactSha256'
	];
	if (Object.keys(value).sort().join('|') !== [...names].sort().join('|')) {
		throw new Error('artifact bundle has an unexpected field');
	}
	if (value.kind !== 'bark_bitvm_verifier_artifacts_v1') {
		throw new Error('wrong artifact bundle kind');
	}
	for (const name of names.slice(1)) {
		if (typeof value[name] !== 'string' || !/^[0-9a-f]{64}$/.test(value[name])) {
			throw new Error(`artifact bundle ${name} must be 32-byte lowercase hex`);
		}
	}
	return cloneJson(value);
}

function artifactBundleDigest(bundle) {
	return taggedHash(
		'bark-bitvm-showcase/verifier-artifact-bundle/v1',
		normalizeArtifactBundle(bundle)
	);
}

function verifierKeyId(publicKey) {
	return sha256Hex(publicKey.export({ type: 'spki', format: 'der' }));
}

function createIndependentVerifier() {
	const signer = crypto.generateKeyPairSync('ed25519');
	const publicKeyPem = signer.publicKey.export({ type: 'spki', format: 'pem' });
	const keyId = verifierKeyId(signer.publicKey);
	const identity = deepFreeze({ keyId, publicKeyPem });

	function factsFor(bundle) {
		const normalized = normalizeArtifactBundle(bundle);
		const claimIsGeneric = normalized.claimInputSha256 ===
			CLAIM_INPUT_SPECS['generic-owner-exit'].sha256;
		const claimIsBark = normalized.claimInputSha256 ===
			CLAIM_INPUT_SPECS['bark-native-owner-exit'].sha256;
		const proofMatches =
			(claimIsGeneric && normalized.proofArtifactSha256 ===
				ARTIFACT_BUNDLES.honest_generic.proofArtifactSha256) ||
			(claimIsBark && normalized.proofArtifactSha256 ===
				ARTIFACT_BUNDLES.honest_bark_test_double.proofArtifactSha256);
		return {
			claim_binding_matches: claimIsGeneric || claimIsBark,
			pinned_stwo_statement_verified: proofMatches,
			shinigami_engine_check_verified: normalized.shinigamiArtifactSha256 ===
				ARTIFACT_BUNDLES.honest_generic.shinigamiArtifactSha256
		};
	}

	function attest(materialInput, contextInput) {
		const material = normalizeArtifactMaterial(materialInput);
		const bundle = deriveArtifactBundle(material);
		const context = normalizeAttestationContext(contextInput);
		const payload = {
			kind: 'bark_bitvm_independent_verifier_attestation_v1',
			version: 1,
			verifierKeyId: keyId,
			policyHash: context.policyHash,
			network: context.network,
			caseId: context.caseId,
			requestNonce: context.requestNonce,
			artifactBundleSha256: artifactBundleDigest(bundle),
			claimInputSha256: bundle.claimInputSha256,
			facts: factsFor(bundle)
		};
		const signature = crypto.sign(
			null,
			Buffer.from(canonicalStringify(payload), 'utf8'),
			signer.privateKey
		).toString('hex');
		return deepFreeze({
			artifactBundle: bundle,
			attestation: { ...payload, signature }
		});
	}

	return Object.freeze({ identity, attest });
}

function verifyIndependentAttestation(
	policy,
	artifactMaterialInput,
	claimedBundleInput,
	attestationInput,
	contextInput
) {
	try {
		const material = normalizeArtifactMaterial(artifactMaterialInput);
		const bundle = deriveArtifactBundle(material);
		const claimedBundle = normalizeArtifactBundle(claimedBundleInput);
		if (canonicalStringify(claimedBundle) !== canonicalStringify(bundle)) {
			throw new Error('claimed artifact hashes do not match supplied artifact bytes');
		}
		const context = normalizeAttestationContext(contextInput);
		if (context.policyHash !== policy.policyHash ||
			context.network !== policy.core.network) {
			throw new Error('verifier request context does not match the pinned policy');
		}
		const attestation = cloneJson(attestationInput);
		const names = [
			'kind', 'version', 'verifierKeyId', 'policyHash', 'network',
			'caseId', 'requestNonce', 'artifactBundleSha256',
			'claimInputSha256', 'facts', 'signature'
		];
		if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation) ||
			Object.keys(attestation).sort().join('|') !== [...names].sort().join('|')) {
			throw new Error('verifier attestation has an unexpected schema');
		}
		if (attestation.kind !== 'bark_bitvm_independent_verifier_attestation_v1' ||
			attestation.version !== 1) {
			throw new Error('wrong verifier attestation kind or version');
		}
		if (attestation.verifierKeyId !== policy.core.factProvider.keyId) {
			throw new Error('independent verifier key substitution rejected');
		}
		if (attestation.policyHash !== context.policyHash ||
			attestation.network !== context.network ||
			attestation.caseId !== context.caseId ||
			attestation.requestNonce !== context.requestNonce) {
			throw new Error('independent verifier attestation request context mismatch');
		}
		const bundleSha256 = artifactBundleDigest(bundle);
		if (attestation.artifactBundleSha256 !== bundleSha256 ||
			attestation.claimInputSha256 !== bundle.claimInputSha256) {
			throw new Error('verifier attestation is not bound to the proposed artifacts');
		}
		const facts = normalizeFacts(attestation.facts, 'attested facts');
		if (typeof attestation.signature !== 'string' ||
			!/^[0-9a-f]{128}$/.test(attestation.signature)) {
			throw new Error('verifier attestation signature is malformed');
		}
		const { signature, ...payload } = attestation;
		const publicKey = crypto.createPublicKey(policy.core.factProvider.publicKeyPem);
		if (verifierKeyId(publicKey) !== policy.core.factProvider.keyId ||
			!crypto.verify(
				null,
				Buffer.from(canonicalStringify(payload), 'utf8'),
				publicKey,
				Buffer.from(signature, 'hex')
			)) {
			throw new Error('independent verifier signature is invalid');
		}
		return {
			ok: true,
			facts,
			artifactBundle: bundle,
			artifactBundleSha256: bundleSha256,
			attestationSha256: taggedHash(
				'bark-bitvm-showcase/verifier-attestation/v1',
				attestation
			)
		};
	} catch (error) {
		return { ok: false, reason: error.message };
	}
}

function runGit(repo, args) {
	const result = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
	if (result.error) throw new Error(`git failed to start: ${result.error.message}`);
	return result;
}

function loadPinnedApis(repoInput) {
	const repo = path.resolve(repoInput);
	const commit = runGit(repo, ['cat-file', '-e', `${PINNED_UTXOREF_COMMIT}^{commit}`]);
	if (commit.status !== 0) throw new Error('the pinned UTXORef commit is unavailable');
	const head = runGit(repo, ['rev-parse', 'HEAD']);
	if (head.status !== 0 || head.stdout.trim() !== PINNED_UTXOREF_COMMIT) {
		throw new Error('UTXORef HEAD is not the pinned commit');
	}
	const diff = runGit(repo, ['diff', '--quiet', PINNED_UTXOREF_COMMIT, '--', ...REQUIRED_UTXOREF_FILES]);
	if (diff.status !== 0) {
		throw new Error('the loaded UTXORef dependency closure differs from the pinned commit');
	}
	for (const relative of REQUIRED_UTXOREF_FILES) {
		if (!fs.existsSync(path.join(repo, relative))) throw new Error(`missing UTXORef file: ${relative}`);
	}
	const sourceBlobs = REQUIRED_UTXOREF_FILES.map((relative) => {
		const blob = runGit(repo, ['rev-parse', `${PINNED_UTXOREF_COMMIT}:${relative}`]);
		if (blob.status !== 0 || !/^[0-9a-f]{40}$/.test(blob.stdout.trim())) {
			throw new Error(`unable to resolve pinned UTXORef blob: ${relative}`);
		}
		return { path: relative, gitBlob: blob.stdout.trim() };
	});
	const referee = path.join(repo, 'bitvm3', 'utxo_referee');
	const sourceDigest = taggedHash(
		'bark-bitvm-showcase/utxoref-source-closure/v1',
		sourceBlobs
	);
	if (sourceDigest !== PINNED_UTXOREF_SOURCE_DIGEST) {
		throw new Error(`pinned UTXORef source digest changed: ${sourceDigest}`);
	}
	return {
		utxoref: require(path.join(referee, 'utxoref_v2.js')),
		trace: require(path.join(referee, 'bitvm_trace_v2.js')),
		assertion: require(path.join(referee, 'bitvm_assertion_graph_v2.js')),
		adaptor: require(path.join(referee, 'tradelayer_dlc_adaptor_sig.js')),
		sourceDigest
	};
}

function randomScalar(adaptor) {
	for (;;) {
		const candidate = adaptor.bufToBig(crypto.randomBytes(32)) % adaptor.N;
		if (candidate !== 0n) return candidate;
	}
}

function normalizeFacts(value, fieldName = 'facts') {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error(`${fieldName} must be an object`);
	}
	const normalized = {};
	for (const key of FACT_KEYS) {
		if (typeof value[key] !== 'boolean') throw new Error(`${fieldName}.${key} must be boolean`);
		normalized[key] = value[key];
	}
	if (Object.keys(value).sort().join('|') !== [...FACT_KEYS].sort().join('|')) {
		throw new Error(`${fieldName} has an unexpected fact label`);
	}
	return normalized;
}

function factsEqual(left, right) {
	return FACT_KEYS.every((key) => left[key] === right[key]);
}

function allFactsTrue(facts) {
	return FACT_KEYS.every((key) => facts[key] === true);
}

function traceValues(facts) {
	const claim = Number(facts.claim_binding_matches);
	const stwo = Number(facts.pinned_stwo_statement_verified);
	const shinigami = Number(facts.shinigami_engine_check_verified);
	const proofBound = claim & stwo;
	return {
		claim_binding_matches: claim,
		pinned_stwo_statement_verified: stwo,
		proof_bound: proofBound,
		shinigami_engine_check_verified: shinigami,
		authorization_assertion: proofBound & shinigami
	};
}

function makePolicy(coreInput) {
	const core = cloneJson(coreInput);
	const policy = {
		kind: 'bark_bitvm_trusted_cosigner_policy',
		version: 1,
		core,
		policyHash: taggedHash(POLICY_DOMAIN, core)
	};
	return deepFreeze(policy);
}

function policyValidation(proposed, trusted) {
	if (!proposed || proposed.kind !== trusted.kind || proposed.version !== trusted.version) {
		return { ok: false, reason: 'wrong policy kind or version' };
	}
	const selfHash = taggedHash(POLICY_DOMAIN, proposed.core);
	if (proposed.policyHash !== selfHash) return { ok: false, reason: 'proposed policy self-hash is invalid' };
	if (proposed.policyHash !== trusted.policyHash ||
		canonicalStringify(proposed.core) !== canonicalStringify(trusted.core)) {
		return { ok: false, reason: 'policy substitution rejected' };
	}
	return { ok: true };
}

function stateVerification(policy, apis) {
	const publicKey = crypto.createPublicKey(policy.core.stateSigner.publicKeyPem);
	assert.equal(apis.utxoref.publicKeyId(publicKey), policy.core.stateSigner.keyId);
	return {
		trustedSigners: { [policy.core.stateSigner.keyId]: publicKey },
		expectedNetwork: policy.core.network,
		expectedGenesisHash: policy.core.genesisHash,
		currentHeight: 1002
	};
}

function buildStateBody(
	policy,
	caseId,
	facts,
	disclosures,
	claimInputSha256,
	artifactBundleSha256,
	verifierAttestationSha256,
	requestNonce
) {
	const contractId = taggedHash('bark-bitvm-showcase/contract/v1', {
		policyHash: policy.policyHash,
		caseId
	});
	return {
		network: policy.core.network,
		chainGenesisHash: policy.core.genesisHash,
		contractId,
		epochId: '1',
		snapshotHeight: 1000,
		snapshotBlockHash: taggedHash('bark-bitvm-showcase/snapshot/v1', { caseId }),
		marks: {
			trustedCosignerGate: {
				policyHash: policy.policyHash,
				caseId,
				claimInputSha256,
				artifactBundleSha256,
				verifierAttestationSha256,
				requestNonce,
				recomputedFacts: facts,
				operatorDisclosures: disclosures,
				disclosureMatchesRecomputation: factsEqual(facts, disclosures),
				trustedVerifierNotBitcoinStwo: true
			}
		},
		settlementAddressMap: {
			A: { address: 'demo-beneficiary-a', scriptPubKeyHex: `0014${'01'.repeat(20)}` },
			C: { address: 'demo-beneficiary-c', scriptPubKeyHex: `0014${'03'.repeat(20)}` }
		},
		pnlRows: [
			{
				id: 'demo-a-wins', contractId, side: 'long', entryPrice: 2100,
				closePrice: 2200, quantityUnits: 30, collateralSats: 50000,
				traderAddress: 'A', counterpartyAddress: 'B'
			},
			{
				id: 'demo-c-wins', contractId, side: 'long', entryPrice: 2100,
				closePrice: 2200, quantityUnits: 20, collateralSats: 50000,
				traderAddress: 'C', counterpartyAddress: 'B'
			}
		]
	};
}

function buildOperatorTrace(
	apis,
	policy,
	caseId,
	disclosures,
	claimInputSha256,
	artifactBundleSha256,
	verifierAttestationSha256,
	requestNonce,
	challengerXonly
) {
	const values = traceValues(disclosures);
	const labels = Object.keys(values);
	const wireBundle = apis.trace.buildWireSecretSetV2(labels);
	const publicTrace = apis.trace.buildPublicTraceV2({
		circuitId: policy.core.circuit.id,
		binding: {
			kind: 'bark_bitvm_operator_disclosure_v1',
			policyHash: policy.policyHash,
			caseId,
			claimInputSha256,
			artifactBundleSha256,
			verifierAttestationSha256,
			requestNonce,
			disclosureHash: taggedHash('bark-bitvm-showcase/disclosure/v1', disclosures)
		},
		gates: policy.core.circuit.gates,
		wireBundle,
		values
	});
	const traceCheck = apis.trace.verifyPublicTraceV2(publicTrace);
	const template = apis.assertion.buildBitvmAssertionTemplateV2({
		network: policy.core.network,
		publicTrace,
		expectedInputs: policy.core.circuit.expectedInputs,
		operatorXonly: policy.core.operatorXonly,
		challengerXonly,
		challengeCsvBlocks: policy.core.challengeCsvBlocks,
		recoveryCsvBlocks: policy.core.recoveryCsvBlocks
	});
	const templateCheck = apis.assertion.verifyBitvmAssertionTemplateV2(template, publicTrace);
	const inputDisprove = apis.trace.findInputBindingDisproveV2(
		publicTrace,
		policy.core.circuit.expectedInputs,
		challengerXonly
	);
	const gateDisprove = apis.trace.findGateDisproveV2(publicTrace, challengerXonly);
	return {
		publicTrace,
		template,
		summary: {
			traceVerified: traceCheck.ok,
			templateVerified: templateCheck.ok,
			authorizationBit: values.authorization_assertion === 1,
			inputDisproveConstructible: Boolean(inputDisprove),
			gateDisproveConstructible: Boolean(gateDisprove)
		}
	};
}

function buildSignedGraph(apis, options) {
	const {
		policy, caseId, facts, disclosures, claimInputSha256,
		artifactBundleSha256, verifierAttestationSha256, requestNonce,
		stateSignerPrivateKey,
		operatorSecret, challengerSecret
	} = options;
	const stateEnvelope = apis.utxoref.buildSignedStateCheckpointV2(
		buildStateBody(
			policy,
			caseId,
			facts,
			disclosures,
			claimInputSha256,
			artifactBundleSha256,
			verifierAttestationSha256,
			requestNonce
		),
		{
			privateKey: stateSignerPrivateKey,
			publicKey: crypto.createPublicKey(policy.core.stateSigner.publicKeyPem)
		}
	);
	const verification = stateVerification(policy, apis);
	const stateCheck = apis.utxoref.verifySignedStateCheckpointV2(stateEnvelope, verification);
	if (!stateCheck.ok) throw new Error(`trusted state did not verify: ${stateCheck.reason}`);
	const binding = apis.assertion.buildSettlementTraceBindingV2({ stateEnvelope, feeSats: '1000' });
	const values = traceValues(disclosures);
	const publicTrace = apis.trace.buildPublicTraceV2({
		circuitId: policy.core.circuit.id,
		binding,
		gates: policy.core.circuit.gates,
		wireBundle: apis.trace.buildWireSecretSetV2(Object.keys(values)),
		values
	});
	const template = apis.assertion.buildBitvmAssertionTemplateV2({
		network: policy.core.network,
		publicTrace,
		expectedInputs: policy.core.circuit.expectedInputs,
		operatorXonly: policy.core.operatorXonly,
		challengerXonly: policy.core.challengerXonly,
		challengeCsvBlocks: policy.core.challengeCsvBlocks,
		recoveryCsvBlocks: policy.core.recoveryCsvBlocks
	});
	const assertionOutpoint = {
		txid: taggedHash('bark-bitvm-showcase/assertion-outpoint/v1', {
			policyHash: policy.policyHash,
			caseId,
			traceRoot: publicTrace.traceRoot
		}),
		vout: 0,
		amountSats: binding.assertionAmountSats,
		scriptPubKeyHex: template.p2trScriptPubKey
	};
	const graph = apis.assertion.finalizeBitvmAssertionGraphV2({
		template,
		publicTrace,
		stateEnvelope,
		stateVerification: verification,
		assertionOutpoint,
		feeSats: binding.feeSats,
		recoveryFeeSats: '500',
		recoveryScriptPubKeyHex: RECOVERY_SPK,
		operatorSecret,
		challengerSecret
	});
	const graphCheck = apis.assertion.verifyBitvmAssertionGraphV2(graph, verification);
	return { graph, graphCheck, stateEnvelope, stateVerification: verification };
}

function createTrustedGate(apis, operatorXonly, verifierIdentity) {
	// Neither private value is reachable through the returned gate object.
	const challengerSecret = randomScalar(apis.adaptor);
	const challengerXonly = apis.adaptor.xOnlyPubkey(challengerSecret).toString('hex');
	const stateSigner = crypto.generateKeyPairSync('ed25519');
	const stateSignerPublicPem = stateSigner.publicKey.export({ type: 'spki', format: 'pem' });
	const stateSignerKeyId = apis.utxoref.publicKeyId(stateSigner.publicKey);
	const consumedAttestationNonces = new Set();

	const policy = makePolicy({
		domain: POLICY_DOMAIN,
		network: NETWORK,
		genesisHash: GENESIS_HASH,
		utxorefCommit: PINNED_UTXOREF_COMMIT,
		utxorefSourceDigest: apis.sourceDigest,
		operatorXonly,
		challengerXonly,
		stateSigner: { keyId: stateSignerKeyId, publicKeyPem: stateSignerPublicPem },
		challengeCsvBlocks: CHALLENGE_CSV_BLOCKS,
		recoveryCsvBlocks: RECOVERY_CSV_BLOCKS,
		circuit: {
			id: CIRCUIT_ID,
			gates: GATES,
			expectedInputs: EXPECTED_INPUTS
		},
		claimInputs: {
			honest_true: {
				fixture: 'generic-owner-exit',
				sha256: CLAIM_INPUT_SPECS['generic-owner-exit'].sha256
			},
			false_stwo: {
				fixture: 'generic-owner-exit',
				sha256: CLAIM_INPUT_SPECS['generic-owner-exit'].sha256
			},
			bark_true: {
				fixture: 'bark-native-owner-exit',
				sha256: CLAIM_INPUT_SPECS['bark-native-owner-exit'].sha256
			}
		},
		factProvider: {
			kind: 'signed_artifact_bound_blue_team_test_double_v1',
			keyId: verifierIdentity.keyId,
			publicKeyPem: verifierIdentity.publicKeyPem,
			meaning: 'models artifact-bound pinned STWO/Shinigami recomputation outside operator control'
		},
		securityBoundary: {
			bitcoinVerifiesStwo: false,
			bitcoinVerifiesShinigami: false,
			bitcoinRequiresTrustedCosignerForFastSettlement: true
		}
	});

	function reject(reason, recomputedFacts = null, traceSummary = null, artifactBundleSha256 = null) {
		return {
			accepted: false,
			reason,
			recomputedFacts,
			trace: traceSummary,
			artifactBundleSha256,
			fundingAuthorized: false,
			fastSettlementSignaturePackageIssued: false,
			graphVerified: null
		};
	}

	function evaluateUnchecked(proposal, operatorSecret) {
		const policyCheck = policyValidation(proposal.proposedPolicy, policy);
		if (!policyCheck.ok) return reject(policyCheck.reason);
		if (proposal.operatorXonly !== policy.core.operatorXonly) return reject('operator key substitution rejected');
		if (proposal.challengerXonly !== policy.core.challengerXonly) {
			return reject('challenger/cosigner key substitution rejected');
		}
		if (proposal.stateSignerKeyId !== policy.core.stateSigner.keyId) {
			return reject('state signer key substitution rejected');
		}
		const disclosures = normalizeFacts(proposal.operatorDisclosures, 'operator disclosures');
		const claimInput = cloneJson(proposal.claimInput);
		const claimInputSha256 = sha256Hex(canonicalCairoJson(claimInput));
		const attestationContext = {
			policyHash: policy.policyHash,
			network: policy.core.network,
			caseId: proposal.caseId,
			requestNonce: proposal.requestNonce
		};
		const attestationCheck = verifyIndependentAttestation(
			policy,
			proposal.artifactMaterial,
			proposal.claimedArtifactBundle,
			proposal.verifierAttestation,
			attestationContext
		);
		if (!attestationCheck.ok) return reject(attestationCheck.reason);
		if (consumedAttestationNonces.has(proposal.requestNonce)) {
			return reject('independent verifier attestation nonce was already consumed');
		}
		const recomputedFacts = attestationCheck.facts;
		const artifactBundleSha256 = attestationCheck.artifactBundleSha256;
		const verifierAttestationSha256 = attestationCheck.attestationSha256;
		const inspected = buildOperatorTrace(
			apis,
			policy,
			proposal.caseId,
			disclosures,
			claimInputSha256,
			artifactBundleSha256,
			verifierAttestationSha256,
			proposal.requestNonce,
			policy.core.challengerXonly
		);
		const expectedClaim = policy.core.claimInputs[proposal.caseId];
		if (!expectedClaim || claimInputSha256 !== expectedClaim.sha256 ||
			claimInputSha256 !== attestationCheck.artifactBundle.claimInputSha256) {
			return reject(
				'full canonical claim-input digest substitution rejected',
				recomputedFacts,
				inspected.summary,
				artifactBundleSha256
			);
		}
		if (!factsEqual(recomputedFacts, disclosures)) {
			return reject(
				'operator disclosures differ from independent recomputation',
				recomputedFacts,
				inspected.summary,
				artifactBundleSha256
			);
		}
		if (!allFactsTrue(recomputedFacts)) {
			return reject(
				'independent facts do not authorize fast settlement',
				recomputedFacts,
				inspected.summary,
				artifactBundleSha256
			);
		}
		const built = buildSignedGraph(apis, {
			policy,
			caseId: proposal.caseId,
			facts: recomputedFacts,
			disclosures,
			claimInputSha256,
			artifactBundleSha256,
			verifierAttestationSha256,
			requestNonce: proposal.requestNonce,
			stateSignerPrivateKey: stateSigner.privateKey,
			operatorSecret,
			challengerSecret
		});
		if (!built.graphCheck.ok) return reject(`UTXORef graph rejected: ${built.graphCheck.reason}`);
		consumedAttestationNonces.add(proposal.requestNonce);
		return {
			accepted: true,
			reason: 'exact policy, independent facts, state signature, and BIP340 graph verified',
			recomputedFacts,
			trace: inspected.summary,
			fundingAuthorized: true,
			fastSettlementSignaturePackageIssued: true,
			graphVerified: true,
			claimInputSha256,
			artifactBundleSha256,
			verifierAttestationSha256,
			requestNonce: proposal.requestNonce,
			artifactMaterial: cloneJson(proposal.artifactMaterial),
			artifactBundle: cloneJson(attestationCheck.artifactBundle),
			verifierAttestation: cloneJson(proposal.verifierAttestation),
			graphHash: built.graph.graphHash,
			assertionTreeRoot: built.graph.template.assertionTreeRoot,
			settlementSighash: built.graph.settlementPath.sighash,
			operatorSignature: built.graph.settlementPath.operatorSignature,
			challengerSignature: built.graph.settlementPath.challengerSignature,
			assertionOutpoint: built.graph.assertionOutpoint,
			publicGraph: built.graph,
			settlementSignaturePresent: /^[0-9a-f]{128}$/.test(
				built.graph.settlementPath.challengerSignature
			),
			privateMaterialExposed: false
		};
	}

	function evaluate(proposal, operatorSecret) {
		try {
			return evaluateUnchecked(proposal, operatorSecret);
		} catch (error) {
			return reject(`malformed proposal rejected: ${error.message}`);
		}
	}

	return Object.freeze({ policy, evaluate });
}

function defaultArtifactMaterial(caseId) {
	if (caseId === 'honest_true') return cloneJson(ARTIFACT_MATERIALS.honest_generic);
	if (caseId === 'false_stwo') return cloneJson(ARTIFACT_MATERIALS.false_stwo);
	if (caseId === 'bark_true') return cloneJson(ARTIFACT_MATERIALS.honest_bark_test_double);
	return cloneJson(ARTIFACT_MATERIALS.honest_generic);
}

function proposalFor(gate, verifier, operatorXonly, caseId, disclosures, overrides = {}) {
	const expectedClaim = gate.policy.core.claimInputs[caseId];
	const {
		artifactMaterial: overriddenMaterial,
		claimedArtifactBundle: overriddenClaimedBundle,
		verifierAttestation: overriddenAttestation,
		requestNonce: overriddenNonce,
		...otherOverrides
	} = overrides;
	const artifactMaterial = overriddenMaterial || defaultArtifactMaterial(caseId);
	const requestNonce = overriddenNonce || crypto.randomBytes(32).toString('hex');
	const signed = verifier.attest(artifactMaterial, {
		policyHash: gate.policy.policyHash,
		network: gate.policy.core.network,
		caseId,
		requestNonce
	});
	const claimedArtifactBundle = overriddenClaimedBundle || signed.artifactBundle;
	const verifierAttestation = overriddenAttestation || signed.attestation;
	return {
		caseId,
		operatorDisclosures: disclosures,
		claimInput: expectedClaim ? loadClaimInput(expectedClaim.fixture) : [],
		artifactMaterial,
		claimedArtifactBundle,
		verifierAttestation,
		requestNonce,
		proposedPolicy: cloneJson(gate.policy),
		operatorXonly,
		challengerXonly: gate.policy.core.challengerXonly,
		stateSignerKeyId: gate.policy.core.stateSigner.keyId,
		...otherOverrides
	};
}

function buildRoguePolicy(apis, trustedPolicy, operatorXonly) {
	const challengerSecret = randomScalar(apis.adaptor);
	const stateSigner = crypto.generateKeyPairSync('ed25519');
	const publicKeyPem = stateSigner.publicKey.export({ type: 'spki', format: 'pem' });
	const core = cloneJson(trustedPolicy.core);
	core.operatorXonly = operatorXonly;
	core.challengerXonly = apis.adaptor.xOnlyPubkey(challengerSecret).toString('hex');
	core.stateSigner = {
		keyId: apis.utxoref.publicKeyId(stateSigner.publicKey),
		publicKeyPem
	};
	return { policy: makePolicy(core), challengerSecret, stateSigner };
}

function parseArgs(argv) {
	let utxorefRepo = DEFAULT_UTXOREF_REPO;
	for (let index = 0; index < argv.length; index += 2) {
		if (argv[index] !== '--utxoref-repo' || !argv[index + 1]) {
			throw new Error('usage: trusted-cosigner-gate.js [--utxoref-repo PATH]');
		}
		utxorefRepo = argv[index + 1];
	}
	return { utxorefRepo };
}

function runMatrix(apis) {
	const operatorSecret = randomScalar(apis.adaptor);
	const operatorXonly = apis.adaptor.xOnlyPubkey(operatorSecret).toString('hex');
	const verifier = createIndependentVerifier();
	const gate = createTrustedGate(apis, operatorXonly, verifier.identity);
	const allTrue = {
		claim_binding_matches: true,
		pinned_stwo_statement_verified: true,
		shinigami_engine_check_verified: true
	};
	const disclosedFalse = { ...allTrue, pinned_stwo_statement_verified: false };

	const honestProposal = proposalFor(
		gate,
		verifier,
		operatorXonly,
		'honest_true',
		allTrue
	);
	const honest = gate.evaluate(honestProposal, operatorSecret);
	assert.equal(honest.accepted, true);
	assert.equal(honest.graphVerified, true);
	assert.equal(honest.settlementSignaturePresent, true);
	const replayedHonestAttestation = gate.evaluate(honestProposal, operatorSecret);
	assert.equal(replayedHonestAttestation.accepted, false);
	assert.match(replayedHonestAttestation.reason, /nonce was already consumed/);
	assert.equal(replayedHonestAttestation.fastSettlementSignaturePackageIssued, false);
	const honestGraphVerification = apis.assertion.verifyBitvmAssertionGraphV2(
		honest.publicGraph,
		stateVerification(gate.policy, apis)
	);
	assert.equal(honestGraphVerification.ok, true);

	const genericCollisionInput = amountDelayCollision(loadClaimInput('generic-owner-exit'));
	const genericCollision = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'honest_true', allTrue, {
			claimInput: genericCollisionInput
		}),
		operatorSecret
	);
	assert.equal(genericCollision.accepted, false);
	assert.equal(genericCollision.trace.traceVerified, true);
	assert.equal(genericCollision.trace.inputDisproveConstructible, false);
	assert.match(genericCollision.reason, /full canonical claim-input digest substitution/);

	const barkCollisionInput = amountDelayCollision(loadClaimInput('bark-native-owner-exit'));
	const barkCollision = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'bark_true', allTrue, {
			claimInput: barkCollisionInput
		}),
		operatorSecret
	);
	assert.equal(barkCollision.accepted, false);
	assert.equal(barkCollision.trace.traceVerified, true);
	assert.equal(barkCollision.trace.inputDisproveConstructible, false);
	assert.match(barkCollision.reason, /full canonical claim-input digest substitution/);

	const genericLimbCollisionInput = settlementLimbCollision(
		loadClaimInput('generic-owner-exit')
	);
	const genericLimbCollision = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'honest_true', allTrue, {
			claimInput: genericLimbCollisionInput
		}),
		operatorSecret
	);
	assert.equal(genericLimbCollision.accepted, false);
	assert.equal(genericLimbCollision.trace.inputDisproveConstructible, false);
	assert.match(genericLimbCollision.reason, /full canonical claim-input digest substitution/);

	const barkLimbCollisionInput = settlementLimbCollision(
		loadClaimInput('bark-native-owner-exit')
	);
	const barkLimbCollision = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'bark_true', allTrue, {
			claimInput: barkLimbCollisionInput
		}),
		operatorSecret
	);
	assert.equal(barkLimbCollision.accepted, false);
	assert.equal(barkLimbCollision.trace.inputDisproveConstructible, false);
	assert.match(barkLimbCollision.reason, /full canonical claim-input digest substitution/);

	const allOnesLie = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'false_stwo', allTrue),
		operatorSecret
	);
	assert.equal(allOnesLie.accepted, false);
	assert.equal(allOnesLie.trace.traceVerified, true);
	assert.equal(allOnesLie.trace.templateVerified, true);
	assert.equal(allOnesLie.trace.inputDisproveConstructible, false);
	assert.equal(allOnesLie.fastSettlementSignaturePackageIssued, false);

	const relabelledFalseArtifact = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'honest_true', allTrue, {
			artifactMaterial: cloneJson(ARTIFACT_MATERIALS.false_stwo)
		}),
		operatorSecret
	);
	assert.equal(relabelledFalseArtifact.accepted, false);
	assert.equal(relabelledFalseArtifact.trace.traceVerified, true);
	assert.equal(relabelledFalseArtifact.trace.inputDisproveConstructible, false);
	assert.match(relabelledFalseArtifact.reason, /disclosures differ from independent recomputation/);

	const falseBytesClaimedHonest = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'honest_true', allTrue, {
			artifactMaterial: cloneJson(ARTIFACT_MATERIALS.false_stwo),
			claimedArtifactBundle: cloneJson(ARTIFACT_BUNDLES.honest_generic)
		}),
		operatorSecret
	);
	assert.equal(falseBytesClaimedHonest.accepted, false);
	assert.equal(falseBytesClaimedHonest.graphVerified, null);
	assert.match(
		falseBytesClaimedHonest.reason,
		/claimed artifact hashes do not match supplied artifact bytes/
	);

	const honestFalseDisclosure = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'false_stwo', disclosedFalse),
		operatorSecret
	);
	assert.equal(honestFalseDisclosure.accepted, false);
	assert.equal(honestFalseDisclosure.trace.inputDisproveConstructible, true);
	assert.equal(honestFalseDisclosure.fastSettlementSignaturePackageIssued, false);

	const rogue = buildRoguePolicy(apis, gate.policy, operatorXonly);
	const rogueKeyProposal = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'false_stwo', allTrue, {
			challengerXonly: rogue.policy.core.challengerXonly
		}),
		operatorSecret
	);
	assert.equal(rogueKeyProposal.accepted, false);
	assert.match(rogueKeyProposal.reason, /challenger\/cosigner key substitution/);

	const rogueSignerProposal = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'false_stwo', allTrue, {
			stateSignerKeyId: rogue.policy.core.stateSigner.keyId
		}),
		operatorSecret
	);
	assert.equal(rogueSignerProposal.accepted, false);
	assert.match(rogueSignerProposal.reason, /state signer key substitution/);

	const substitutedCore = cloneJson(gate.policy.core);
	substitutedCore.challengeCsvBlocks = CHALLENGE_CSV_BLOCKS + 1;
	const substitutedPolicy = makePolicy(substitutedCore);
	const policySubstitution = gate.evaluate(
		proposalFor(gate, verifier, operatorXonly, 'honest_true', allTrue, {
			proposedPolicy: cloneJson(substitutedPolicy)
		}),
		operatorSecret
	);
	assert.equal(policySubstitution.accepted, false);
	assert.match(policySubstitution.reason, /policy substitution/);

	// A rogue operator can make a graph that is valid under its own self-selected
	// signer and challenger. That does not make it admissible under the fixed policy.
	const rogueGraph = buildSignedGraph(apis, {
		policy: rogue.policy,
		caseId: 'rogue_self_trust',
		facts: allTrue,
		disclosures: allTrue,
		claimInputSha256: CLAIM_INPUT_SPECS['generic-owner-exit'].sha256,
		artifactBundleSha256: artifactBundleDigest(ARTIFACT_BUNDLES.honest_generic),
		verifierAttestationSha256: taggedHash(
			'bark-bitvm-showcase/rogue-attestation/v1',
			{ caseId: 'rogue_self_trust' }
		),
		requestNonce: sha256Hex('bark-bitvm-showcase/rogue-request-nonce/v1'),
		stateSignerPrivateKey: rogue.stateSigner.privateKey,
		operatorSecret,
		challengerSecret: rogue.challengerSecret
	});
	assert.equal(rogueGraph.graphCheck.ok, true);
	const fixedTrustCheck = apis.assertion.verifyBitvmAssertionGraphV2(
		rogueGraph.graph,
		stateVerification(gate.policy, apis)
	);
	assert.equal(fixedTrustCheck.ok, false);
	assert.match(fixedTrustCheck.reason, /state signer is not allowlisted/);

	function rejectedResult(result) {
		const caught = result.accepted === false &&
			result.fastSettlementSignaturePackageIssued === false &&
			result.fundingAuthorized === false;
		return {
			trustedCosignatureIssued: result.fastSettlementSignaturePackageIssued,
			fundingAuthorized: result.fundingAuthorized,
			caught,
			reason: result.reason,
			passed: caught
		};
	}

	const matrix = [
		{
			attack: 'honest-independent-facts',
			externalTruth: true,
			operatorDisclosedAllOnes: true,
			publicTraceValid: honest.trace.traceVerified,
			bitvmDisproveConstructible: honest.trace.inputDisproveConstructible,
			trustedCosignatureIssued: honest.fastSettlementSignaturePackageIssued,
			utxorefGraphVerified: honest.graphVerified,
			fundingAuthorized: honest.fundingAuthorized,
			caught: false,
			passed: honest.accepted && honest.graphVerified &&
				honest.fastSettlementSignaturePackageIssued && honest.fundingAuthorized
		},
		{
			attack: 'generic-linear-binding-collision-substitution',
			linearBindingUnchanged: computeLinearBinding(genericCollisionInput) ===
				computeLinearBinding(loadClaimInput('generic-owner-exit')),
			fullClaimDigestMatched: false,
			publicTraceValid: genericCollision.trace.traceVerified,
			bitvmDisproveConstructible: genericCollision.trace.inputDisproveConstructible,
			...rejectedResult(genericCollision)
		},
		{
			attack: 'bark-linear-binding-collision-substitution',
			linearBindingUnchanged: computeLinearBinding(barkCollisionInput) ===
				computeLinearBinding(loadClaimInput('bark-native-owner-exit')),
			fullClaimDigestMatched: false,
			publicTraceValid: barkCollision.trace.traceVerified,
			bitvmDisproveConstructible: barkCollision.trace.inputDisproveConstructible,
			...rejectedResult(barkCollision)
		},
		{
			attack: 'generic-settlement-limb-collision-substitution',
			linearBindingUnchanged: computeLinearBinding(genericLimbCollisionInput) ===
				computeLinearBinding(loadClaimInput('generic-owner-exit')),
			fullClaimDigestMatched: false,
			publicTraceValid: genericLimbCollision.trace.traceVerified,
			bitvmDisproveConstructible: genericLimbCollision.trace.inputDisproveConstructible,
			...rejectedResult(genericLimbCollision)
		},
		{
			attack: 'bark-settlement-limb-collision-substitution',
			linearBindingUnchanged: computeLinearBinding(barkLimbCollisionInput) ===
				computeLinearBinding(loadClaimInput('bark-native-owner-exit')),
			fullClaimDigestMatched: false,
			publicTraceValid: barkLimbCollision.trace.traceVerified,
			bitvmDisproveConstructible: barkLimbCollision.trace.inputDisproveConstructible,
			...rejectedResult(barkLimbCollision)
		},
		{
			attack: 'dishonest-operator-false-all-ones',
			externalTruth: false,
			operatorDisclosedAllOnes: true,
			publicTraceValid: allOnesLie.trace.traceVerified,
			bitvmDisproveConstructible: allOnesLie.trace.inputDisproveConstructible,
			trustedCosignatureIssued: allOnesLie.fastSettlementSignaturePackageIssued,
			utxorefGraphVerificationStatus: 'not-attempted',
			caughtBy: 'independent recomputation and withheld settlement cosignature',
			...rejectedResult(allOnesLie)
		},
		{
			attack: 'false-artifact-relabelled-as-honest-case',
			proposalCaseId: 'honest_true',
			attestedStwoVerified: relabelledFalseArtifact.recomputedFacts
				.pinned_stwo_statement_verified,
			publicTraceValid: relabelledFalseArtifact.trace.traceVerified,
			bitvmDisproveConstructible: relabelledFalseArtifact.trace
				.inputDisproveConstructible,
			utxorefGraphVerificationStatus: 'not-attempted',
			...rejectedResult(relabelledFalseArtifact)
		},
		{
			attack: 'false-artifact-bytes-with-claimed-honest-hashes',
			proposalCaseId: 'honest_true',
			claimedBundleSha256: artifactBundleDigest(ARTIFACT_BUNDLES.honest_generic),
			derivedBundleSha256: artifactBundleDigest(ARTIFACT_BUNDLES.false_stwo),
			claimedHashesMatchSuppliedBytes: false,
			utxorefGraphVerificationStatus: 'not-attempted',
			...rejectedResult(falseBytesClaimedHonest)
		},
		{
			attack: 'false-fact-disclosed-as-zero',
			externalTruth: false,
			operatorDisclosedAllOnes: false,
			publicTraceValid: honestFalseDisclosure.trace.traceVerified,
			bitvmDisproveConstructible: honestFalseDisclosure.trace.inputDisproveConstructible,
			caughtBy: 'UTXORef input-binding evidence plus cosigner denial',
			...rejectedResult(honestFalseDisclosure)
		},
		{
			attack: 'rogue-challenger-key-substitution',
			rogueGraphCouldBeSelfVerified: true,
			...rejectedResult(rogueKeyProposal)
		},
		{
			attack: 'self-allowlisted-state-signer',
			rogueGraphSelfTrustVerified: rogueGraph.graphCheck.ok,
			fixedPolicyVerificationPassed: fixedTrustCheck.ok,
			fixedPolicyReason: fixedTrustCheck.reason,
			...rejectedResult(rogueSignerProposal)
		},
		{
			attack: 'internally-valid-policy-substitution',
			proposedPolicySelfHashValid: policyValidation(substitutedPolicy, substitutedPolicy).ok,
			matchesPinnedFundingPolicy: false,
			...rejectedResult(policySubstitution)
		}
	];

	assert.equal(matrix.every((entry) => entry.passed), true);
	const serialized = JSON.stringify(matrix);
	assert.equal(/"(?:challengerSecret|operatorSecret|privateKey)"/.test(serialized), false);

	return {
		schema: 'bark-bitvm-trusted-cosigner-red-blue-matrix-v1',
		verdict: 'all blue-team gates behaved as expected',
		policy: {
			policyHash: gate.policy.policyHash,
			utxorefCommit: gate.policy.core.utxorefCommit,
			utxorefSourceDigest: gate.policy.core.utxorefSourceDigest,
			operatorXonly: gate.policy.core.operatorXonly,
			challengerXonly: gate.policy.core.challengerXonly,
			stateSignerKeyId: gate.policy.core.stateSigner.keyId,
			factProviderKeyId: gate.policy.core.factProvider.keyId,
			claimInputSha256ByCase: Object.fromEntries(Object.entries(
				gate.policy.core.claimInputs
			).map(([caseId, spec]) => [caseId, spec.sha256])),
			challengeCsvBlocks: gate.policy.core.challengeCsvBlocks,
			recoveryCsvBlocks: gate.policy.core.recoveryCsvBlocks,
			fixedBeforeFunding: Object.isFrozen(gate.policy) &&
				policyValidation(gate.policy, gate.policy).ok
		},
		policyCore: gate.policy.core,
		honestReceipt: {
			graphHash: honest.graphHash,
			assertionTreeRoot: honest.assertionTreeRoot,
			settlementSighash: honest.settlementSighash,
			operatorSignature: honest.operatorSignature,
			challengerSignature: honest.challengerSignature,
			assertionOutpoint: honest.assertionOutpoint,
			claimInputSha256: honest.claimInputSha256,
			artifactBundleSha256: honest.artifactBundleSha256,
			verifierAttestationSha256: honest.verifierAttestationSha256,
			requestNonce: honest.requestNonce,
			utxorefGraphVerified: honest.graphVerified
		},
		honestTranscript: {
			artifactMaterial: honest.artifactMaterial,
			artifactBundle: honest.artifactBundle,
			verifierAttestation: honest.verifierAttestation,
			graph: honest.publicGraph,
			graphVerification: honestGraphVerification
		},
		securityBoundary: {
			model: 'independent-trusted-verifier-and-bitcoin-settlement-cosigner',
			recomputedFactsOverrideOperatorDisclosures: true,
			challengerPrivateKeyExposed: false,
			bitcoinVerifiesBip340SettlementCosignature: true,
			bitcoinVerifiesStwo: false,
			bitcoinVerifiesShinigami: false,
			allOnesLieHasBitvmDisprove: false,
			allOnesLieBlockedBeforeFunding: true,
			fullCanonicalClaimDigestPinned: true,
			linearBindingCollisionsBlockedBeforeFunding: true,
			artifactHashesDerivedFromSuppliedBytes: true,
			artifactBytesAreSyntheticTestDouble: true,
			artifactBytesLoadedFromTrustedStorage: false,
			attestationBoundToPolicyCaseAndNonce: true,
			attestationNonceConsumptionPersisted: false,
			actualStwoShinigamiExecutionInsideVerifier: false,
			factsSelectedBySignedArtifactAttestation: true,
			operatorCaseLabelSelectsFacts: false,
			emergencyRecoveryStillExistsAfterLongCsv: true,
			notTrustlessZkEnforcement: true,
			fundedOrBroadcast: false,
			syntheticAssertionOutpoint: true,
			sameProcessTestDouble: true,
			operatorSecretPassedIntoCosignerClosure: true,
			nonCustodialSignerSeparationDemonstrated: false,
			note: 'The independent verifier is a same-process test double over small synthetic artifact bytes; production must isolate keys, hash and rerun actual pinned STWO/Shinigami artifacts internally, accept only a prepared transaction, and persist nonce consumption before signing.'
		},
		matrix
	};
}

function main() {
	const args = parseArgs(process.argv.slice(2));
	const apis = loadPinnedApis(args.utxorefRepo);
	console.log(JSON.stringify(runMatrix(apis), null, 2));
}

try {
	main();
} catch (error) {
	console.error(`trusted-cosigner-gate failed: ${error.message}`);
	process.exitCode = 1;
}
