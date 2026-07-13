#!/usr/bin/env node
'use strict';

const assert = require('assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const PINNED_UTXOREF_COMMIT = '13f43d7f7bbddf10fa507770645ef05e49189441';
const PINNED_UTXOREF_SOURCE_DIGEST = '3d3c65dd4f1f206357baf0aeea6aa1c0b85a5f2a2a6656ab04c120fe28450899';
const POLICY_DOMAIN = 'bark-bitvm-showcase/trusted-cosigner-policy/v1';
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
		typeof value === 'string') return JSON.stringify(value);
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

function taggedHash(tag, value) {
	return sha256Hex(Buffer.concat([
		Buffer.from(`${tag}\0`, 'utf8'),
		Buffer.from(canonicalStringify(value), 'utf8')
	]));
}

function parseArgs(argv) {
	const result = {};
	for (let index = 0; index < argv.length; index += 2) {
		const flag = argv[index];
		const value = argv[index + 1];
		if (!['--input', '--utxoref-repo'].includes(flag) || !value) {
			throw new Error('usage: verify-blue-evidence.js --input FILE --utxoref-repo DIR');
		}
		if (result[flag]) throw new Error(`duplicate argument: ${flag}`);
		result[flag] = value;
	}
	if (!result['--input'] || !result['--utxoref-repo']) {
		throw new Error('both --input and --utxoref-repo are required');
	}
	return { input: path.resolve(result['--input']), utxorefRepo: path.resolve(result['--utxoref-repo']) };
}

function exactKeys(value, names, label) {
	assert(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
	assert.deepEqual(Object.keys(value).sort(), [...names].sort(), `${label} schema changed`);
}

function canonicalBase64Bytes(value, label) {
	assert.equal(typeof value, 'string', `${label} must be base64`);
	const bytes = Buffer.from(value, 'base64');
	assert(bytes.length > 0, `${label} must not be empty`);
	assert.equal(bytes.toString('base64'), value, `${label} must be canonical base64`);
	return bytes;
}

function runGit(repo, args) {
	const result = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
	if (result.error || result.status !== 0) throw new Error(`git ${args.join(' ')} failed`);
	return result.stdout.trim();
}

function verifyEvidence(input, utxorefRepo) {
	const blue = JSON.parse(fs.readFileSync(input, 'utf8'));
	assert.equal(blue.schema, 'bark-bitvm-trusted-cosigner-red-blue-matrix-v1');
	assert.equal(runGit(utxorefRepo, ['rev-parse', 'HEAD']), PINNED_UTXOREF_COMMIT);
	assert.equal(
		runGit(utxorefRepo, ['status', '--porcelain', '--', ...REQUIRED_UTXOREF_FILES]),
		'',
		'UTXORef dependency closure is dirty'
	);
	const sourceBlobs = REQUIRED_UTXOREF_FILES.map((relative) => {
		assert.equal(fs.existsSync(path.join(utxorefRepo, relative)), true, `missing ${relative}`);
		const gitBlob = runGit(utxorefRepo, [
			'rev-parse', `${PINNED_UTXOREF_COMMIT}:${relative}`
		]);
		assert.match(gitBlob, /^[0-9a-f]{40}$/);
		return { path: relative, gitBlob };
	});
	const sourceDigest = taggedHash(
		'bark-bitvm-showcase/utxoref-source-closure/v1', sourceBlobs
	);
	assert.equal(sourceDigest, PINNED_UTXOREF_SOURCE_DIGEST);

	const policyHash = taggedHash(POLICY_DOMAIN, blue.policyCore);
	assert.equal(policyHash, blue.policy.policyHash, 'policy hash mismatch');
	assert.equal(blue.policyCore.utxorefCommit, PINNED_UTXOREF_COMMIT);
	assert.equal(blue.policyCore.utxorefSourceDigest, sourceDigest);

	const transcript = blue.honestTranscript;
	const material = transcript.artifactMaterial;
	exactKeys(material, [
		'kind', 'claimInputBase64', 'proofArtifactBase64', 'shinigamiArtifactBase64'
	], 'artifact material');
	assert.equal(material.kind, 'bark_bitvm_verifier_artifact_bytes_v1');
	const bundle = {
		kind: 'bark_bitvm_verifier_artifacts_v1',
		claimInputSha256: sha256Hex(canonicalBase64Bytes(material.claimInputBase64, 'claim bytes')),
		proofArtifactSha256: sha256Hex(canonicalBase64Bytes(material.proofArtifactBase64, 'proof bytes')),
		shinigamiArtifactSha256: sha256Hex(
			canonicalBase64Bytes(material.shinigamiArtifactBase64, 'Shinigami bytes')
		)
	};
	assert.equal(canonicalStringify(bundle), canonicalStringify(transcript.artifactBundle));
	assert.equal(bundle.claimInputSha256, blue.policyCore.claimInputs.honest_true.sha256);
	assert.equal(bundle.claimInputSha256, blue.honestReceipt.claimInputSha256);
	const artifactBundleSha256 = taggedHash(
		'bark-bitvm-showcase/verifier-artifact-bundle/v1', bundle
	);
	assert.equal(artifactBundleSha256, blue.honestReceipt.artifactBundleSha256);

	const attestation = transcript.verifierAttestation;
	exactKeys(attestation, [
		'kind', 'version', 'verifierKeyId', 'policyHash', 'network', 'caseId',
		'requestNonce', 'artifactBundleSha256', 'claimInputSha256', 'facts', 'signature'
	], 'verifier attestation');
	assert.equal(attestation.kind, 'bark_bitvm_independent_verifier_attestation_v1');
	assert.equal(attestation.version, 1);
	exactKeys(attestation.facts, [
		'claim_binding_matches', 'pinned_stwo_statement_verified',
		'shinigami_engine_check_verified'
	], 'attested facts');
	for (const value of Object.values(attestation.facts)) assert.equal(value, true);
	const { signature, ...payload } = attestation;
	assert.equal(attestation.policyHash, policyHash);
	assert.equal(attestation.network, blue.policyCore.network);
	assert.equal(attestation.caseId, 'honest_true');
	assert.equal(attestation.requestNonce, blue.honestReceipt.requestNonce);
	assert.equal(attestation.artifactBundleSha256, artifactBundleSha256);
	assert.equal(attestation.claimInputSha256, bundle.claimInputSha256);
	const verifierKey = crypto.createPublicKey(blue.policyCore.factProvider.publicKeyPem);
	const verifierKeyId = sha256Hex(verifierKey.export({ type: 'spki', format: 'der' }));
	assert.equal(verifierKeyId, blue.policy.factProviderKeyId);
	assert.equal(verifierKeyId, attestation.verifierKeyId);
	assert.equal(
		crypto.verify(
			null,
			Buffer.from(canonicalStringify(payload), 'utf8'),
			verifierKey,
			Buffer.from(signature, 'hex')
		),
		true,
		'independent verifier signature failed'
	);
	const attestationSha256 = taggedHash(
		'bark-bitvm-showcase/verifier-attestation/v1', attestation
	);
	assert.equal(attestationSha256, blue.honestReceipt.verifierAttestationSha256);
	const stateMark = transcript.graph.settlement.stateEnvelope.body.marks.trustedCosignerGate;
	exactKeys(stateMark, [
		'policyHash', 'caseId', 'claimInputSha256', 'artifactBundleSha256',
		'verifierAttestationSha256', 'requestNonce', 'recomputedFacts',
		'operatorDisclosures', 'disclosureMatchesRecomputation',
		'trustedVerifierNotBitcoinStwo'
	], 'signed trusted-cosigner state mark');
	assert.equal(stateMark.policyHash, attestation.policyHash);
	assert.equal(stateMark.caseId, attestation.caseId);
	assert.equal(stateMark.claimInputSha256, attestation.claimInputSha256);
	assert.equal(stateMark.artifactBundleSha256, attestation.artifactBundleSha256);
	assert.equal(stateMark.verifierAttestationSha256, attestationSha256);
	assert.equal(stateMark.requestNonce, attestation.requestNonce);
	assert.equal(canonicalStringify(stateMark.recomputedFacts), canonicalStringify(attestation.facts));
	assert.equal(canonicalStringify(stateMark.operatorDisclosures), canonicalStringify(attestation.facts));
	assert.equal(stateMark.disclosureMatchesRecomputation, true);
	assert.equal(stateMark.trustedVerifierNotBitcoinStwo, true);

	const referee = path.join(utxorefRepo, 'bitvm3', 'utxo_referee');
	const utxoref = require(path.join(referee, 'utxoref_v2.js'));
	const assertion = require(path.join(referee, 'bitvm_assertion_graph_v2.js'));
	const stateSignerKey = crypto.createPublicKey(blue.policyCore.stateSigner.publicKeyPem);
	assert.equal(utxoref.publicKeyId(stateSignerKey), blue.policyCore.stateSigner.keyId);
	const graphCheck = assertion.verifyBitvmAssertionGraphV2(transcript.graph, {
		trustedSigners: { [blue.policyCore.stateSigner.keyId]: stateSignerKey },
		expectedNetwork: blue.policyCore.network,
		expectedGenesisHash: blue.policyCore.genesisHash,
		currentHeight: 1002
	});
	assert.equal(graphCheck.ok, true, 'UTXORef graph verification failed');
	assert.equal(graphCheck.fraudCount, 0);
	assert.equal(canonicalStringify(graphCheck), canonicalStringify(transcript.graphVerification));
	assert.equal(graphCheck.graphHash, blue.honestReceipt.graphHash);

	return {
		schema: 'bark-bitvm-blue-evidence-independent-audit-v1',
		utxorefSourceClosureVerified: true,
		policyHashVerified: true,
		artifactBytesRehashed: true,
		artifactBundleDigestVerified: true,
		attestationSignatureVerified: true,
		attestationContextVerified: true,
		attestationDigestVerified: true,
		allTrueFactsVerified: true,
		attestationStateCrossLinkVerified: true,
		stateSignerKeyVerified: true,
		utxorefGraphVerified: true,
		fraudCount: graphCheck.fraudCount,
		graphHash: graphCheck.graphHash
	};
}

try {
	const args = parseArgs(process.argv.slice(2));
	process.stdout.write(`${JSON.stringify(verifyEvidence(args.input, args.utxorefRepo), null, 2)}\n`);
} catch (error) {
	process.stderr.write(`verify-blue-evidence failed: ${error.message}\n`);
	process.exitCode = 1;
}
