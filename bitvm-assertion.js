#!/usr/bin/env node

/*
 * Verify the pinned demo artifacts and bind the resulting external assertions
 * into UTXORef's V2 optimistic assertion/disprove graph. Bitcoin Script does
 * not verify STWO or Shinigami in this demo.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const EXPECTED_UTXOREF_COMMIT = '13f43d7f7bbddf10fa507770645ef05e49189441';
const EXPECTED_SHINIGAMI_COMMIT = '7e8c05d60b4bd7ae91ddc18a42e8e13090286f0c';
const EXPECTED_SCARB_SHA256 = 'e86974d48a6aa25403f69e1eae3dfe1d6ece7f12a8e5de6f7a2eb3d96f76bd71';
const EXPECTED_STWO_VERIFIER_SHA256 = '4b3dc11dffd8bda4481d662cef7e4778393588935dc8fcf9d4e4ee154c06850b';
const EXPECTED_EXECUTABLE_SHA256 = 'cb7d5111087d1defd85eaf6aaaf3b5442a286fc16391df014dedc9283faa9bfa';
const EXPECTED_CAIRO_SOURCE_SHA256 = 'ab422d117be16af2a2754a838769b4fa19b97f694af88309a82233669f59c472';
const CAIRO_PRIME = (1n << 251n) + (17n << 192n) + 1n;

const CASES = {
	owner_exit_allow: {
		claimInputSha256: '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b',
		proofFixtureSha256: '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b',
		proofFile: 'ark_zk_miniscript_owner_csv_exit.proof.json',
		proofSha256: 'd11bf6d8624efde5b9023da9b228385b52e6f2f02b3e110a1dc80fc0b7f5054b',
		proofRole: 2n,
		proofBinding: 0x4d4226614ba0e3cf8e3061925ddcc0f4ee8d463a5an,
		shinigamiTest: 'test_opcode_checksequence_block',
		expectClaimMatch: true
	},
	owner_exit_challenge: {
		claimInputSha256: '565c91be50cde7cb99c08acb9c1120ec99b3a68bd1277a723fc56663abfda273',
		proofFixtureSha256: '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b',
		proofFile: 'ark_zk_miniscript_owner_csv_exit.proof.json',
		proofSha256: 'd11bf6d8624efde5b9023da9b228385b52e6f2f02b3e110a1dc80fc0b7f5054b',
		proofRole: 2n,
		proofBinding: 0x4d4226614ba0e3cf8e3061925ddcc0f4ee8d463a5an,
		shinigamiTest: 'test_opcode_checksequence_fail',
		expectClaimMatch: false
	},
	virtual_cet_guard: {
		claimInputSha256: '9562a25859130a168f9b03ffc57928a573a576b94279099417f080c57ac1deb3',
		proofFixtureSha256: '9562a25859130a168f9b03ffc57928a573a576b94279099417f080c57ac1deb3',
		proofFile: 'ark_zk_miniscript_dlc_virtual_cet_settlement.proof.json',
		proofSha256: 'a39afc7e1577f0f5eb6514539778845401f04b0459201029e04244e1eefdedea',
		proofRole: 4n,
		proofBinding: 0x30954eeff3ef6e0f0bb22ac53d9a5c672b198935d4n,
		shinigamiTest: null,
		expectClaimMatch: true
	}
};

const UTXOREF_FILES = [
	'utxoref_v2.js', 'bitvm_trace_v2.js', 'bitvm_assertion_graph_v2.js',
	'tradelayer_dlc_adaptor_sig.js', 'm1_spec.js',
	'tradelayer_bitvm_circuit.js', 'tradelayer_taproot.js',
	'tradelayer_pnl_route_adapter.js', 'tradelayer_pnl_state_netting.js',
	'tradelayer_taproot_script.js', 'tradelayer_taproot_tree.js',
	'tradelayer_bitvm_dispute.js', 'types.js', 'm1_chain_env.js',
	'tradelayer_bitvm_gadgets.js', 'merkle.js', 'verify.js'
].map((name) => `bitvm3/utxo_referee/${name}`);

const OPERATOR_SECRET = 0x12345n;
const CHALLENGER_SECRET = 0x67890n;
const RECOVERY_SPK = `0014${'09'.repeat(20)}`;
const CHALLENGE_SPK = `0014${'08'.repeat(20)}`;

function fail(message) {
	throw new Error(message);
}

function sha256(value) {
	return crypto.createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
	return sha256(value).toString('hex');
}

function fileSha256(file) {
	return sha256Hex(fs.readFileSync(file));
}

function requireFileHash(file, expected, label) {
	const actual = fileSha256(file);
	if (actual !== expected) fail(`${label} hash ${actual} does not match ${expected}`);
}

function runChecked(executable, args, options, label) {
	const result = spawnSync(executable, args, {
		...options,
		encoding: 'utf8',
		maxBuffer: 64 * 1024 * 1024
	});
	if (result.error) fail(`${label} failed to start: ${result.error.message}`);
	const output = `${result.stdout || ''}\n${result.stderr || ''}`;
	if (result.status !== 0) fail(`${label} failed (${result.status}): ${output.slice(-4000)}`);
	return output;
}

function deterministicRandom(seed) {
	let counter = 0;
	return (size) => {
		if (size !== 32) fail(`unexpected deterministic RNG request: ${size}`);
		counter += 1;
		return sha256(Buffer.from(`${seed}:${counter}`, 'utf8'));
	};
}

function parseArgs(argv) {
	const args = {};
	for (let index = 0; index < argv.length; index += 2) {
		const key = argv[index];
		const value = argv[index + 1];
		if (!key || !key.startsWith('--') || value === undefined) fail('invalid arguments');
		args[key.slice(2)] = value;
	}
	for (const required of [
		'receipt', 'output', 'proof', 'cairo-executable', 'stwo-verifier',
		'shinigami-repo', 'shinigami-scarb', 'shinigami-target', 'utxoref-repo'
	]) {
		if (!args[required]) fail(`missing --${required}`);
	}
	return args;
}

function gitHead(repo) {
	return execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}

function requireCleanPaths(repo, paths, label) {
	const result = spawnSync('git', ['-C', repo, 'diff', '--quiet', 'HEAD', '--', ...paths]);
	if (result.error) fail(`${label} git check failed: ${result.error.message}`);
	if (result.status !== 0) fail(`${label} relevant files differ from pinned HEAD`);
}

function loadApis(repo) {
	repo = path.resolve(repo);
	if (gitHead(repo) !== EXPECTED_UTXOREF_COMMIT) fail('UTXORef commit is not pinned');
	requireCleanPaths(repo, UTXOREF_FILES, 'UTXORef');
	for (const relative of UTXOREF_FILES) {
		if (!fs.existsSync(path.join(repo, relative))) fail(`missing UTXORef module: ${relative}`);
	}
	const referee = path.join(repo, 'bitvm3', 'utxo_referee');
	return {
		utxoref: require(path.join(referee, 'utxoref_v2.js')),
		trace: require(path.join(referee, 'bitvm_trace_v2.js')),
		assertion: require(path.join(referee, 'bitvm_assertion_graph_v2.js')),
		adaptor: require(path.join(referee, 'tradelayer_dlc_adaptor_sig.js'))
	};
}

function feltFromLimbs(limbs) {
	if (!Array.isArray(limbs) || limbs.length !== 8) fail('invalid STWO felt limbs');
	return limbs.reduceRight((value, limb) => (value << 32n) + BigInt(limb), 0n);
}

function parseExecutableFelt(encoded) {
	const value = encoded.startsWith('-0x')
		? -BigInt(`0x${encoded.slice(3)}`)
		: BigInt(encoded);
	return value < 0n ? value + CAIRO_PRIME : value;
}

function canonicalCairoJson(fields) {
	if (!Array.isArray(fields) || fields.length !== 25) fail('claim must contain 25 Cairo fields');
	return `[\n${fields.map((field) => `  "${field}"`).join(',\n')}\n]\n`;
}

function verifyReceipt(receipt, expected) {
	if (receipt.schema !== 'bark-shinigami-composed-demo-v2') fail('unsupported receipt schema');
	if (!CASES[receipt.case_id]) fail('unknown demo case');
	if (receipt.claim.cairo_source_sha256 !== EXPECTED_CAIRO_SOURCE_SHA256) {
		fail('receipt Cairo source pin mismatch');
	}
	const claimJson = canonicalCairoJson(receipt.claim.cairo_input);
	const claimHash = sha256Hex(claimJson);
	if (claimHash !== expected.claimInputSha256 || receipt.claim.claim_input_sha256 !== claimHash) {
		fail('receipt claim input does not match the pinned case');
	}
	if (receipt.claim.proof_fixture_sha256 !== expected.proofFixtureSha256) {
		fail('receipt proof-fixture provenance mismatch');
	}
	const role = BigInt(receipt.claim.cairo_input[6]);
	const binding = BigInt(receipt.claim.cairo_input[24]);
	if (Number(role) !== receipt.claim.role_code || receipt.claim.binding_commitment !== `0x${binding.toString(16)}`) {
		fail('receipt claim metadata is internally inconsistent');
	}
	const claimMatches = role === expected.proofRole && binding === expected.proofBinding;
	if (claimMatches !== expected.expectClaimMatch ||
		receipt.claim.binding_matches_expected_proof !== claimMatches) {
		fail('receipt claim/proof binding decision is inconsistent');
	}
	if (receipt.stwo.expected_proof_file !== expected.proofFile ||
		receipt.stwo.expected_proof_sha256 !== expected.proofSha256) {
		fail('receipt proof pin mismatch');
	}
	return { claimHash, role, binding, claimMatches };
}

function verifyStwoStatement(args, receipt, expected) {
	if (path.basename(args.proof) !== expected.proofFile) fail('unexpected proof filename');
	requireFileHash(args.proof, expected.proofSha256, 'STWO proof');
	requireFileHash(args['stwo-verifier'], EXPECTED_STWO_VERIFIER_SHA256, 'STWO verifier');
	requireFileHash(args['cairo-executable'], EXPECTED_EXECUTABLE_SHA256, 'Cairo executable');

	const proof = JSON.parse(fs.readFileSync(args.proof, 'utf8'));
	const executable = JSON.parse(fs.readFileSync(args['cairo-executable'], 'utf8'));
	const publicData = proof?.claim?.public_data;
	const program = publicData?.public_memory?.program;
	const bytecode = executable?.program?.bytecode;
	if (!Array.isArray(program) || !Array.isArray(bytecode) || program.length !== 1744 || bytecode.length !== 1744) {
		fail('unexpected authenticated Cairo program length');
	}
	for (let index = 0; index < program.length; index += 1) {
		if (feltFromLimbs(program[index][1]) !== parseExecutableFelt(bytecode[index])) {
			fail(`proof program differs from pinned executable at felt ${index}`);
		}
	}
	const initial = publicData.initial_state;
	const final = publicData.final_state;
	const outputSegment = publicData.public_memory.public_segments.output;
	if (initial.pc !== 1 || initial.ap !== 1747 || initial.fp !== 1747 ||
		final.pc !== 5 || final.ap !== 2111 || final.fp !== 1747 ||
		outputSegment.start_ptr.value !== 2111 || outputSegment.stop_ptr.value !== 2114) {
		fail('unexpected authenticated Cairo execution state');
	}
	const output = publicData.public_memory.output.map((entry) => feltFromLimbs(entry[1]));
	if (output.length !== 3 || output[0] !== 1n || output[1] !== expected.proofRole ||
		output[2] !== expected.proofBinding ||
		output[1] !== BigInt(receipt.stwo.expected_role_code) ||
		`0x${output[2].toString(16)}` !== receipt.stwo.expected_binding_commitment) {
		fail('authenticated STWO output does not match the pinned public statement');
	}
	const verifierOutput = runChecked(
		args['stwo-verifier'], ['--proof_path', args.proof, '--channel_hash', 'blake2s'], {},
		'STWO verifier'
	);
	if (!/verified successfully/i.test(verifierOutput)) fail('STWO verifier omitted success marker');
	return {
		proofSha256: expected.proofSha256,
		programMatchesExecutable: true,
		publicOutput: output.map((value) => `0x${value.toString(16)}`),
		publicOutputMatchesPinnedStatement: true,
		freshlyVerified: true
	};
}

function toCairoByteArrayFields(text) {
	const bytes = Buffer.from(text, 'utf8');
	const fullWords = [];
	let offset = 0;
	while (bytes.length - offset > 31) {
		fullWords.push(BigInt(`0x${bytes.subarray(offset, offset + 31).toString('hex')}`).toString());
		offset += 31;
	}
	const pending = bytes.subarray(offset);
	const pendingWord = pending.length === 0 ? '0' : BigInt(`0x${pending.toString('hex')}`).toString();
	return `[${fullWords.join(',')}],${pendingWord},${pending.length}`;
}

function verifyShinigami(args, receipt, expected) {
	if (gitHead(args['shinigami-repo']) !== EXPECTED_SHINIGAMI_COMMIT) {
		fail('Shinigami commit is not pinned');
	}
	requireCleanPaths(
		args['shinigami-repo'], ['.tool-versions', 'Scarb.toml', 'Scarb.lock', 'packages'], 'Shinigami'
	);
	requireFileHash(args['shinigami-scarb'], EXPECTED_SCARB_SHA256, 'Scarb');
	const env = { ...process.env, SCARB_TARGET_DIR: path.resolve(args['shinigami-target']) };
	let output;
	if (expected.shinigamiTest) {
		output = runChecked(
			args['shinigami-scarb'],
			['--offline', 'test', '-p', 'shinigami_tests', '--', '-f', expected.shinigamiTest],
			{ cwd: args['shinigami-repo'], env }, 'Shinigami CSV engine test'
		);
		if (!output.includes(expected.shinigamiTest) || !/1 passed; 0 failed/.test(output)) {
			fail('Shinigami CSV test output did not identify the pinned check');
		}
	} else {
		const scriptSig = '0x04 0x61726b21';
		const scriptPubKey = 'OP_SHA256 0x20 0x748ca95d537765757744fc079f9b1a9d055683c648f8eceda8ec39d6b849e2e3 OP_EQUAL';
		const cairoArgs = `[${toCairoByteArrayFields(scriptSig)},${toCairoByteArrayFields(scriptPubKey)},0,0]`;
		output = runChecked(
			args['shinigami-scarb'],
			['--offline', 'cairo-run', '--package', 'shinigami_cmds', '--function', 'run', cairoArgs],
			{ cwd: args['shinigami-repo'], env }, 'Shinigami SHA-256 engine run'
		);
		if (!/Execution successful/.test(output)) fail('Shinigami run omitted success marker');
	}
	return {
		check: receipt.shinigami.check,
		commit: EXPECTED_SHINIGAMI_COMMIT,
		freshTarget: path.resolve(args['shinigami-target']),
		verified: true
	};
}

function buildStateBody(receipt, checks) {
	return {
		network: 'bitcoin-regtest',
		chainGenesisHash: '00'.repeat(32),
		contractId: checks.claim.claimHash,
		epochId: '1', snapshotHeight: 1000,
		snapshotBlockHash: sha256Hex(`snapshot:${receipt.case_id}`),
		marks: { barkShinigamiReceipt: {
			caseId: receipt.case_id,
			claimInputSha256: checks.claim.claimHash,
			proofSha256: checks.stwo.proofSha256,
			claimBindingMatches: checks.claim.claimMatches,
			pinnedStwoStatementVerified: checks.stwo.freshlyVerified,
			shinigamiEngineCheckVerified: checks.shinigami.verified
		} },
		settlementAddressMap: {
			A: { address: 'demo-beneficiary-a', scriptPubKeyHex: `0014${'01'.repeat(20)}` },
			C: { address: 'demo-beneficiary-c', scriptPubKeyHex: `0014${'03'.repeat(20)}` }
		},
		pnlRows: [
			{ id: 'demo-a-wins', contractId: checks.claim.claimHash, side: 'long', entryPrice: 2100,
				closePrice: 2200, quantityUnits: 30, collateralSats: 50000,
				traderAddress: 'A', counterpartyAddress: 'B' },
			{ id: 'demo-c-wins', contractId: checks.claim.claimHash, side: 'long', entryPrice: 2100,
				closePrice: 2200, quantityUnits: 20, collateralSats: 50000,
				traderAddress: 'C', counterpartyAddress: 'B' }
		]
	};
}

function buildBitvmReport(receipt, receiptFileSha256, checks, apis) {
	const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
	const keyId = apis.utxoref.publicKeyId(publicKey);
	const stateEnvelope = apis.utxoref.buildSignedStateCheckpointV2(
		buildStateBody(receipt, checks), { privateKey, publicKey }
	);
	const stateVerification = {
		trustedSigners: { [keyId]: publicKey }, expectedNetwork: 'bitcoin-regtest',
		expectedGenesisHash: '00'.repeat(32), currentHeight: 1002
	};
	const binding = apis.assertion.buildSettlementTraceBindingV2({ stateEnvelope, feeSats: '1000' });
	const labels = [
		'claim_binding_matches', 'pinned_stwo_statement_verified', 'proof_bound',
		'shinigami_engine_check_verified', 'authorization_assertion'
	];
	const wireBundle = apis.trace.buildWireSecretSetV2(labels, {
		randomBytes: deterministicRandom(receipt.case_id)
	});
	const claimMatches = checks.claim.claimMatches ? 1 : 0;
	const stwoVerified = checks.stwo.freshlyVerified ? 1 : 0;
	const shinigamiVerified = checks.shinigami.verified ? 1 : 0;
	const proofBound = claimMatches & stwoVerified;
	const authorization = proofBound & shinigamiVerified;
	const publicTrace = apis.trace.buildPublicTraceV2({
		circuitId: 'bark-shinigami-pinned-external-assertions-v2', binding,
		gates: [
			{ type: 'and', inputs: ['claim_binding_matches', 'pinned_stwo_statement_verified'], output: 'proof_bound' },
			{ type: 'and', inputs: ['proof_bound', 'shinigami_engine_check_verified'], output: 'authorization_assertion' }
		], wireBundle,
		values: {
			claim_binding_matches: claimMatches,
			pinned_stwo_statement_verified: stwoVerified,
			proof_bound: proofBound,
			shinigami_engine_check_verified: shinigamiVerified,
			authorization_assertion: authorization
		}
	});
	const operatorXonly = apis.adaptor.xOnlyPubkey(OPERATOR_SECRET).toString('hex');
	const challengerXonly = apis.adaptor.xOnlyPubkey(CHALLENGER_SECRET).toString('hex');
	const template = apis.assertion.buildBitvmAssertionTemplateV2({
		network: 'bitcoin-regtest', publicTrace,
		expectedInputs: {
			claim_binding_matches: 1,
			pinned_stwo_statement_verified: 1,
			shinigami_engine_check_verified: 1
		},
		operatorXonly, challengerXonly, challengeCsvBlocks: 6, recoveryCsvBlocks: 144
	});
	const graph = apis.assertion.finalizeBitvmAssertionGraphV2({
		template, publicTrace, stateEnvelope, stateVerification,
		assertionOutpoint: {
			txid: sha256Hex(`assertion:${receipt.case_id}:${checks.claim.claimHash}`),
			vout: 0, amountSats: binding.assertionAmountSats,
			scriptPubKeyHex: template.p2trScriptPubKey
		},
		feeSats: binding.feeSats, recoveryFeeSats: '500',
		recoveryScriptPubKeyHex: RECOVERY_SPK,
		operatorSecret: OPERATOR_SECRET, challengerSecret: CHALLENGER_SECRET,
		operatorAux: Buffer.alloc(32, 1), challengerAux: Buffer.alloc(32, 2),
		recoveryAux: Buffer.alloc(32, 3)
	});
	const graphVerification = apis.assertion.verifyBitvmAssertionGraphV2(graph, stateVerification);
	if (!graphVerification.ok) fail(`BitVM assertion graph failed: ${graphVerification.reason}`);

	let disprove = null;
	let disproveVerification = null;
	if (authorization === 0) {
		disprove = apis.assertion.buildBitvmDisproveV2(graph, {
			stateVerification, fraudType: 'input', challengerSecret: CHALLENGER_SECRET,
			challengerAux: Buffer.alloc(32, 4), feeSats: '400',
			challengeScriptPubKeyHex: CHALLENGE_SPK
		});
		disproveVerification = apis.assertion.verifyBitvmDisproveV2(graph, disprove, stateVerification);
		if (!disproveVerification.ok) fail(`BitVM disprove failed: ${disproveVerification.reason}`);
	} else {
		let rejected = false;
		try {
			apis.assertion.buildBitvmDisproveV2(graph, {
				stateVerification, challengerSecret: CHALLENGER_SECRET,
				feeSats: '400', challengeScriptPubKeyHex: CHALLENGE_SPK
			});
		} catch (error) {
			rejected = /no constructible fraud proof/.test(error.message);
		}
		if (!rejected) fail('honest assertion unexpectedly produced a disprove witness');
	}

	return {
		schema: 'bark-shinigami-bitvm-demo-v2', case_id: receipt.case_id,
		utxoref_commit: EXPECTED_UTXOREF_COMMIT,
		receipt_sha256: receiptFileSha256,
		receipt_hash_semantics: 'raw-file-bytes',
		enforcement_model: 'local-honest-disclosure-assertion-graph',
		adversarial_zk_verifier_enforcement: false,
		checkpoint_self_signed_by_demo: true,
		operator_can_lie_about_external_checks: true,
		bitcoin_verifies_stwo: false,
		funded_or_broadcast: false,
		checks: {
			claim_binding_matches_stwo_output: checks.claim.claimMatches,
			stwo: checks.stwo, shinigami: checks.shinigami
		},
		trace: {
			trace_root: publicTrace.traceRoot, values: publicTrace.reveals,
			authorization_assertion: authorization === 1
		},
		assertion: {
			graph_hash: graph.graphHash, graph_verified: graphVerification.ok,
			p2tr_script_pubkey: template.p2trScriptPubKey,
			assertion_tree_root: template.assertionTreeRoot,
			optimistic_settlement_available_after_csv: true,
			settlement_witness_tx: graph.settlementPath.witnessTxHex,
			recovery_witness_tx: graph.recoveryPath.witnessTxHex
		},
		disprove: disprove ? {
			verified: disproveVerification.ok, fraud_type: disprove.fraudType,
			leaf_id: disprove.leafId, witness_tx: disprove.witnessTxHex,
			must_confirm_before_settlement_timeout: true
		} : null
	};
}

function main() {
	const args = parseArgs(process.argv.slice(2));
	const receiptBytes = fs.readFileSync(args.receipt);
	const receipt = JSON.parse(receiptBytes.toString('utf8'));
	const expected = CASES[receipt.case_id];
	if (!expected) fail('unknown demo case');
	const checks = {
		claim: verifyReceipt(receipt, expected),
		stwo: verifyStwoStatement(args, receipt, expected),
		shinigami: verifyShinigami(args, receipt, expected)
	};
	const report = buildBitvmReport(
		receipt,
		sha256Hex(receiptBytes),
		checks,
		loadApis(args['utxoref-repo'])
	);
	fs.mkdirSync(path.dirname(path.resolve(args.output)), { recursive: true });
	fs.writeFileSync(args.output, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
	console.log(
		`${report.case_id}: graph=${report.assertion.graph_hash} ` +
		`authorization=${report.trace.authorization_assertion} disprove=${Boolean(report.disprove)}`
	);
}

try {
	main();
} catch (error) {
	console.error(`bitvm-assertion demo failed: ${error.message}`);
	process.exit(1);
}
