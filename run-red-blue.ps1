param(
    [string] $UtxoRefRepo = 'C:\projects\UTXORef\UTXO-Ref',
    [string] $TargetRoot = '',
    [string] $OutputDir = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ShowcaseRoot = (Resolve-Path $PSScriptRoot).Path
if (-not $TargetRoot) {
    $TargetRoot = if (Test-Path 'D:\cargo-target') {
        'D:\cargo-target\bark-bitvm-showcase'
    } else {
        Join-Path $ShowcaseRoot 'target'
    }
}
$TargetRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TargetRoot)
if (-not $OutputDir) {
    $runId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $OutputDir = Join-Path $TargetRoot "red-blue-runs\$runId"
}
$OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$RedScript = Join-Path $ShowcaseRoot 'red-team-attacks.js'
$BlueScript = Join-Path $ShowcaseRoot 'trusted-cosigner-gate.js'
$AuditScript = Join-Path $ShowcaseRoot 'verify-blue-evidence.js'
foreach ($required in @($UtxoRefRepo, $RedScript, $BlueScript, $AuditScript)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing red/blue prerequisite: $required"
    }
}

$NodePath = (Get-Command node -ErrorAction Stop).Source
$NodeVersion = (& $NodePath --version).Trim()
if ($LASTEXITCODE -ne 0 -or -not $NodeVersion) {
    throw 'Unable to determine the Node.js runtime version'
}
$GitVersion = (& git --version).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Git is required for the pinned UTXORef checkout'
}
$PowerShellVersion = $PSVersionTable.PSVersion.ToString()
$RedScriptSha256 = (Get-FileHash -LiteralPath $RedScript -Algorithm SHA256).Hash.ToLowerInvariant()
$BlueScriptSha256 = (Get-FileHash -LiteralPath $BlueScript -Algorithm SHA256).Hash.ToLowerInvariant()
$AuditScriptSha256 = (Get-FileHash -LiteralPath $AuditScript -Algorithm SHA256).Hash.ToLowerInvariant()
$RunnerSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()

$ExpectedUtxoRefCommit = '13f43d7f7bbddf10fa507770645ef05e49189441'
$ExpectedUtxoRefSourceDigest = '3d3c65dd4f1f206357baf0aeea6aa1c0b85a5f2a2a6656ab04c120fe28450899'
$RequiredUtxoRefFiles = @(
    'bitvm3/utxo_referee/utxoref_v2.js',
    'bitvm3/utxo_referee/bitvm_trace_v2.js',
    'bitvm3/utxo_referee/bitvm_assertion_graph_v2.js',
    'bitvm3/utxo_referee/tradelayer_dlc_adaptor_sig.js',
    'bitvm3/utxo_referee/m1_spec.js',
    'bitvm3/utxo_referee/tradelayer_bitvm_circuit.js',
    'bitvm3/utxo_referee/tradelayer_taproot.js',
    'bitvm3/utxo_referee/tradelayer_pnl_route_adapter.js',
    'bitvm3/utxo_referee/tradelayer_pnl_state_netting.js',
    'bitvm3/utxo_referee/tradelayer_taproot_script.js',
    'bitvm3/utxo_referee/tradelayer_taproot_tree.js',
    'bitvm3/utxo_referee/tradelayer_bitvm_dispute.js',
    'bitvm3/utxo_referee/types.js',
    'bitvm3/utxo_referee/m1_chain_env.js',
    'bitvm3/utxo_referee/tradelayer_bitvm_gadgets.js',
    'bitvm3/utxo_referee/merkle.js',
    'bitvm3/utxo_referee/verify.js'
)

& git -C $UtxoRefRepo cat-file -e "$ExpectedUtxoRefCommit`^{commit}"
if ($LASTEXITCODE -ne 0) {
    throw "UTXORef source checkout does not contain $ExpectedUtxoRefCommit"
}

# The caller's checkout supplies Git objects only. Exact-file sparse checkout,
# detached HEAD, and disabled CRLF conversion make the executed closure explicit.
$PinnedUtxoRefRepo = Join-Path $OutputDir 'utxoref-pinned'
if (Test-Path -LiteralPath $PinnedUtxoRefRepo) {
    throw "Pinned checkout path already exists: $PinnedUtxoRefRepo"
}
& git clone --quiet --shared --no-checkout $UtxoRefRepo $PinnedUtxoRefRepo
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to create the isolated UTXORef clone'
}
& git -C $PinnedUtxoRefRepo config core.autocrlf false
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to disable line-ending conversion in the isolated checkout'
}
& git -C $PinnedUtxoRefRepo sparse-checkout init --no-cone
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to initialize the isolated UTXORef sparse checkout'
}
& git -C $PinnedUtxoRefRepo sparse-checkout set --no-cone @RequiredUtxoRefFiles
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to select the reviewed UTXORef dependency closure'
}
& git -C $PinnedUtxoRefRepo checkout --quiet --detach $ExpectedUtxoRefCommit
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to check out the pinned UTXORef commit'
}
$actualCommit = (& git -C $PinnedUtxoRefRepo rev-parse HEAD).Trim()
$status = (& git -C $PinnedUtxoRefRepo status --porcelain) -join "`n"
if ($LASTEXITCODE -ne 0 -or $actualCommit -ne $ExpectedUtxoRefCommit -or $status) {
    throw 'The isolated UTXORef checkout is not clean and exactly pinned'
}
foreach ($relative in $RequiredUtxoRefFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $PinnedUtxoRefRepo $relative))) {
        throw "Pinned UTXORef closure is missing $relative"
    }
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory)] [object] $Object,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Path
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        throw "$Path.$Name is missing"
    }
    return $property.Value
}

function Assert-Boolean {
    param([object] $Object, [string] $Name, [bool] $Expected, [string] $Path)
    $value = Get-RequiredProperty $Object $Name $Path
    if ($value -isnot [bool] -or $value -ne $Expected) {
        throw "$Path.$Name must be Boolean $Expected"
    }
}

function Assert-String {
    param([object] $Object, [string] $Name, [string] $Expected, [string] $Path)
    $value = Get-RequiredProperty $Object $Name $Path
    if ($value -isnot [string] -or $value -cne $Expected) {
        throw "$Path.$Name does not match the reviewed value"
    }
}

function Assert-Integer {
    param([object] $Object, [string] $Name, [long] $Expected, [string] $Path)
    $value = Get-RequiredProperty $Object $Name $Path
    if (($value -isnot [int] -and $value -isnot [long]) -or [long]$value -ne $Expected) {
        throw "$Path.$Name must be integer $Expected"
    }
}

function Assert-Hex64 {
    param([object] $Object, [string] $Name, [string] $Path)
    $value = Get-RequiredProperty $Object $Name $Path
    if ($value -isnot [string] -or $value -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Path.$Name must be 32-byte lowercase hex"
    }
}

function Get-Base64Sha256 {
    param([object] $Object, [string] $Name, [string] $Path)
    $value = Get-RequiredProperty $Object $Name $Path
    if ($value -isnot [string]) {
        throw "$Path.$Name must be canonical base64"
    }
    try {
        $bytes = [Convert]::FromBase64String($value)
    } catch {
        throw "$Path.$Name must be canonical base64"
    }
    if ([Convert]::ToBase64String($bytes) -cne $value) {
        throw "$Path.$Name must use canonical base64 encoding"
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Assert-ExactPropertySet {
    param([object] $Object, [string[]] $Names, [string] $Path)
    if ($null -eq $Object) {
        throw "$Path is missing"
    }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    $difference = Compare-Object -ReferenceObject $expected -DifferenceObject $actual
    if ($null -ne $difference) {
        throw "$Path property set drifted from the reviewed schema"
    }
}

function Assert-NoSensitiveMaterial {
    param(
        [AllowNull()] [object] $Value,
        [Parameter(Mandatory)] [string] $Path
    )
    if ($null -eq $Value -or $Value -is [ValueType]) {
        return
    }
    if ($Value -is [string]) {
        if ($Value -match '-----BEGIN [^-]*PRIVATE KEY-----') {
            throw "$Path contains private-key PEM material"
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable] -and
        $Value -isnot [System.Collections.IDictionary] -and
        $Value -isnot [pscustomobject]) {
        $index = 0
        foreach ($item in $Value) {
            Assert-NoSensitiveMaterial $item "$Path[$index]"
            $index++
        }
        return
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -match '^(?:privateKey|private_key|challengerSecret|operatorSecret|stateSignerPrivateKey|verifierPrivateKey|factProviderPrivateKey|secretKey|secret_key|mnemonic|seed)$') {
            throw "$Path.$($property.Name) is forbidden sensitive material"
        }
        Assert-NoSensitiveMaterial $property.Value "$Path.$($property.Name)"
    }
}

function Invoke-JsonHarness {
    param(
        [Parameter(Mandatory)] [string] $Script,
        [Parameter(Mandatory)] [string] $Destination,
        [string] $InputJson = ''
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $NodePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    # Windows PowerShell targets .NET Framework, whose ProcessStartInfo lacks
    # ArgumentList. Windows paths cannot contain a quote, so explicit quoting is
    # unambiguous here and preserves paths containing spaces.
    $startInfo.Arguments = '"{0}" --utxoref-repo "{1}"' -f $Script, $PinnedUtxoRefRepo
    if ($InputJson) {
        $startInfo.Arguments += ' --input "{0}"' -f $InputJson
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Unable to start $(Split-Path -Leaf $Script)"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $exitCode = $process.ExitCode
    $process.Dispose()

    if ($stdout) {
        [IO.File]::WriteAllText($Destination, $stdout)
    }
    if ($exitCode -ne 0 -or $stderr.Trim()) {
        $failurePath = "$Destination.failure.log"
        [IO.File]::WriteAllText($failurePath, $stderr)
        throw "$(Split-Path -Leaf $Script) failed or wrote to stderr; evidence: $failurePath"
    }
    if (-not $stdout.Trim()) {
        throw "$(Split-Path -Leaf $Script) emitted no JSON"
    }
    try {
        return $stdout | ConvertFrom-Json
    } catch {
        throw "$(Split-Path -Leaf $Script) did not emit one valid JSON document: $($_.Exception.Message)"
    }
}

$RedPath = Join-Path $OutputDir 'red-team.json'
$red = Invoke-JsonHarness -Script $RedScript -Destination $RedPath
Assert-NoSensitiveMaterial $red 'red'
Assert-ExactPropertySet $red @(
    'schema', 'all_attacks_reproduced', 'expected_process_exit', 'threat_boundary', 'attacks'
) 'red'
Assert-String $red 'schema' 'bark-bitvm-red-team-attacks-v1' 'red'
Assert-Boolean $red 'all_attacks_reproduced' $true 'red'
Assert-Integer $red 'expected_process_exit' 0 'red'
Assert-ExactPropertySet $red.attacks @('false_all_ones_graph', 'linear_binding_collisions') 'red.attacks'

$falseAllOnes = $red.attacks.false_all_ones_graph
Assert-ExactPropertySet $falseAllOnes @(
    'attack', 'external_facts_committed_in_signed_checkpoint', 'operator_disclosed_trace_values',
    'self_selected_checkpoint_signer_verified', 'public_trace_verified', 'graph_verified',
    'fraud_count', 'disprove_constructible', 'disprove_error',
    'co_signed_settlement_witness_ready', 'operator_controls_demo_challenger',
    'graph_hash', 'reproduced'
) 'red.attacks.false_all_ones_graph'
Assert-String $falseAllOnes 'attack' 'signed-false-facts_all-ones-public-trace' 'red.false_all_ones'
Assert-Boolean $falseAllOnes 'self_selected_checkpoint_signer_verified' $true 'red.false_all_ones'
Assert-Boolean $falseAllOnes 'public_trace_verified' $true 'red.false_all_ones'
Assert-Boolean $falseAllOnes 'graph_verified' $true 'red.false_all_ones'
Assert-Integer $falseAllOnes 'fraud_count' 0 'red.false_all_ones'
Assert-Boolean $falseAllOnes 'disprove_constructible' $false 'red.false_all_ones'
Assert-Boolean $falseAllOnes 'co_signed_settlement_witness_ready' $true 'red.false_all_ones'
Assert-Boolean $falseAllOnes 'operator_controls_demo_challenger' $true 'red.false_all_ones'
Assert-Boolean $falseAllOnes 'reproduced' $true 'red.false_all_ones'
Assert-String $falseAllOnes 'graph_hash' 'f26ff80f5405debdc19e2d765c5fc2ad1a38e1ab99c4ca9216398b59998cbdfa' 'red.false_all_ones'

$externalFacts = $falseAllOnes.external_facts_committed_in_signed_checkpoint
Assert-ExactPropertySet $externalFacts @(
    'claim_binding_matches', 'pinned_stwo_statement_verified', 'shinigami_engine_check_verified'
) 'red.false_all_ones.external_facts'
foreach ($name in @('claim_binding_matches', 'pinned_stwo_statement_verified', 'shinigami_engine_check_verified')) {
    Assert-Boolean $externalFacts $name $false 'red.false_all_ones.external_facts'
}
$traceValues = $falseAllOnes.operator_disclosed_trace_values
Assert-ExactPropertySet $traceValues @(
    'claim_binding_matches', 'pinned_stwo_statement_verified', 'proof_bound',
    'shinigami_engine_check_verified', 'authorization_assertion'
) 'red.false_all_ones.operator_trace'
foreach ($name in @(
    'claim_binding_matches', 'pinned_stwo_statement_verified', 'proof_bound',
    'shinigami_engine_check_verified', 'authorization_assertion'
)) {
    Assert-Integer $traceValues $name 1 'red.false_all_ones.operator_trace'
}

$ExpectedCollisionHashes = @{
    'generic-owner-exit|amount-plus-one_delay-minus-thirty-one' = '12a3ebe69221663259e2a064633b45049802a10a3a728e43eb6cb7edb5c22914'
    'generic-owner-exit|settlement-high-plus-seventeen_low-minus-thirty-one' = '53a368faa1b7e7bc39a85fdbe888522c3dec6f9dc361f99608c9defaad56dda3'
    'bark-native-owner-exit|amount-plus-one_delay-minus-thirty-one' = '7b8494c262ed23a93ada5ca8eea81d81b992d0742fc737c42e623c108290f334'
    'bark-native-owner-exit|settlement-high-plus-seventeen_low-minus-thirty-one' = 'f515d7e48d15da80230055c9fe93725560f4b9cd024ae6866b02d54ec22ada60'
}
$collisions = @($red.attacks.linear_binding_collisions)
if ($collisions.Count -ne $ExpectedCollisionHashes.Count) {
    throw 'Red team did not emit exactly four collision vectors'
}
$seenCollisions = @{}
foreach ($collision in $collisions) {
    Assert-ExactPropertySet $collision @(
        'fixture', 'family', 'changed_field_indexes', 'original', 'collision',
        'binding_commitment', 'binding_unchanged', 'claim_changed',
        'cairo_binding_check_still_passes'
    ) 'red.collision'
    Assert-Boolean $collision 'binding_unchanged' $true 'red.collision'
    Assert-Boolean $collision 'claim_changed' $true 'red.collision'
    Assert-Boolean $collision 'cairo_binding_check_still_passes' $true 'red.collision'
    $key = "$($collision.fixture)|$($collision.family)"
    if (-not $ExpectedCollisionHashes.ContainsKey($key) -or $seenCollisions.ContainsKey($key)) {
        throw "Unexpected or duplicate collision vector: $key"
    }
    $seenCollisions[$key] = $true
    $expectedClaimProperties = if ($collision.family -eq 'amount-plus-one_delay-minus-thirty-one') {
        @('amount_sats', 'exit_delay', 'input_sha256')
    } else {
        @('high_limb', 'low_limb', 'input_sha256')
    }
    Assert-ExactPropertySet $collision.original $expectedClaimProperties "red.collision[$key].original"
    Assert-ExactPropertySet $collision.collision $expectedClaimProperties "red.collision[$key].collision"
    Assert-Hex64 $collision.original 'input_sha256' "red.collision[$key].original"
    Assert-String $collision.collision 'input_sha256' $ExpectedCollisionHashes[$key] "red.collision[$key]"
    $indexes = @($collision.changed_field_indexes)
    $expectedIndexes = if ($collision.family -eq 'amount-plus-one_delay-minus-thirty-one') { @(22, 23) } else { @(20, 21) }
    if (($indexes -join ',') -ne ($expectedIndexes -join ',')) {
        throw "Collision $key changed unexpected fields"
    }
}

$BluePath = Join-Path $OutputDir 'blue-team.json'
$blue = Invoke-JsonHarness -Script $BlueScript -Destination $BluePath
Assert-NoSensitiveMaterial $blue 'blue'
Assert-ExactPropertySet $blue @(
    'schema', 'verdict', 'policy', 'policyCore', 'honestReceipt',
    'honestTranscript', 'securityBoundary', 'matrix'
) 'blue'
Assert-String $blue 'schema' 'bark-bitvm-trusted-cosigner-red-blue-matrix-v1' 'blue'
Assert-String $blue 'verdict' 'all blue-team gates behaved as expected' 'blue'
Assert-ExactPropertySet $blue.policy @(
    'policyHash', 'utxorefCommit', 'utxorefSourceDigest', 'operatorXonly',
    'challengerXonly', 'stateSignerKeyId', 'factProviderKeyId',
    'claimInputSha256ByCase', 'challengeCsvBlocks',
    'recoveryCsvBlocks', 'fixedBeforeFunding'
) 'blue.policy'
Assert-Hex64 $blue.policy 'policyHash' 'blue.policy'
Assert-String $blue.policy 'utxorefCommit' $ExpectedUtxoRefCommit 'blue.policy'
Assert-String $blue.policy 'utxorefSourceDigest' $ExpectedUtxoRefSourceDigest 'blue.policy'
Assert-Hex64 $blue.policy 'operatorXonly' 'blue.policy'
Assert-Hex64 $blue.policy 'challengerXonly' 'blue.policy'
Assert-Hex64 $blue.policy 'stateSignerKeyId' 'blue.policy'
Assert-Hex64 $blue.policy 'factProviderKeyId' 'blue.policy'
Assert-Integer $blue.policy 'challengeCsvBlocks' 6 'blue.policy'
Assert-Integer $blue.policy 'recoveryCsvBlocks' 144 'blue.policy'
Assert-Boolean $blue.policy 'fixedBeforeFunding' $true 'blue.policy'
if ($blue.policy.operatorXonly -ceq $blue.policy.challengerXonly) {
    throw 'Operator and challenger/cosigner keys must be independent'
}
Assert-ExactPropertySet $blue.policy.claimInputSha256ByCase @(
    'honest_true', 'false_stwo', 'bark_true'
) 'blue.policy.claimInputSha256ByCase'
Assert-String $blue.policy.claimInputSha256ByCase 'honest_true' `
    '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b' `
    'blue.policy.claimInputSha256ByCase'
Assert-String $blue.policy.claimInputSha256ByCase 'false_stwo' `
    '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b' `
    'blue.policy.claimInputSha256ByCase'
Assert-String $blue.policy.claimInputSha256ByCase 'bark_true' `
    '565c91be50cde7cb99c08acb9c1120ec99b3a68bd1277a723fc56663abfda273' `
    'blue.policy.claimInputSha256ByCase'

Assert-ExactPropertySet $blue.policyCore @(
    'domain', 'network', 'genesisHash', 'utxorefCommit', 'utxorefSourceDigest',
    'operatorXonly', 'challengerXonly', 'stateSigner', 'factProvider', 'circuit',
    'claimInputs', 'challengeCsvBlocks', 'recoveryCsvBlocks', 'securityBoundary'
) 'blue.policyCore'

$honestReceipt = $blue.honestReceipt
Assert-ExactPropertySet $honestReceipt @(
    'graphHash', 'assertionTreeRoot', 'settlementSighash', 'operatorSignature',
    'challengerSignature', 'assertionOutpoint', 'claimInputSha256',
    'artifactBundleSha256', 'verifierAttestationSha256', 'requestNonce',
    'utxorefGraphVerified'
) 'blue.honestReceipt'
foreach ($name in @(
    'graphHash', 'assertionTreeRoot', 'settlementSighash',
    'verifierAttestationSha256', 'requestNonce'
)) {
    Assert-Hex64 $honestReceipt $name 'blue.honestReceipt'
}
foreach ($name in @('operatorSignature', 'challengerSignature')) {
    $signature = Get-RequiredProperty $honestReceipt $name 'blue.honestReceipt'
    if ($signature -isnot [string] -or $signature -cnotmatch '^[0-9a-f]{128}$') {
        throw "blue.honestReceipt.$name must be a 64-byte BIP340 signature"
    }
}
Assert-Boolean $honestReceipt 'utxorefGraphVerified' $true 'blue.honestReceipt'
Assert-String $honestReceipt 'claimInputSha256' `
    '5e341808c92820f3fd78ce4ac7687658005fdd0308de9dc26d88cf9b0632be1b' `
    'blue.honestReceipt'
Assert-Hex64 $honestReceipt 'artifactBundleSha256' 'blue.honestReceipt'
Assert-ExactPropertySet $honestReceipt.assertionOutpoint @(
    'txid', 'vout', 'amountSats', 'scriptPubKeyHex'
) 'blue.honestReceipt.assertionOutpoint'
Assert-Hex64 $honestReceipt.assertionOutpoint 'txid' 'blue.honestReceipt.assertionOutpoint'
Assert-Integer $honestReceipt.assertionOutpoint 'vout' 0 'blue.honestReceipt.assertionOutpoint'

$honestTranscript = $blue.honestTranscript
Assert-ExactPropertySet $honestTranscript @(
    'artifactMaterial', 'artifactBundle', 'verifierAttestation', 'graph', 'graphVerification'
) 'blue.honestTranscript'
Assert-ExactPropertySet $honestTranscript.artifactMaterial @(
    'kind', 'claimInputBase64', 'proofArtifactBase64', 'shinigamiArtifactBase64'
) 'blue.honestTranscript.artifactMaterial'
Assert-ExactPropertySet $honestTranscript.artifactBundle @(
    'kind', 'claimInputSha256', 'proofArtifactSha256', 'shinigamiArtifactSha256'
) 'blue.honestTranscript.artifactBundle'
Assert-ExactPropertySet $honestTranscript.verifierAttestation @(
    'kind', 'version', 'verifierKeyId', 'artifactBundleSha256',
    'claimInputSha256', 'policyHash', 'network', 'caseId', 'requestNonce',
    'facts', 'signature'
) 'blue.honestTranscript.verifierAttestation'
Assert-ExactPropertySet $honestTranscript.verifierAttestation.facts @(
    'claim_binding_matches', 'pinned_stwo_statement_verified',
    'shinigami_engine_check_verified'
) 'blue.honestTranscript.verifierAttestation.facts'
Assert-ExactPropertySet $honestTranscript.graph @(
    'kind', 'version', 'publicTrace', 'template', 'assertionOutpoint', 'settlement',
    'settlementPath', 'recoveryPath', 'graphHash'
) 'blue.honestTranscript.graph'
Assert-ExactPropertySet $honestTranscript.graphVerification @(
    'ok', 'graphHash', 'commitmentHash', 'fraudCount', 'p2trScriptPubKey',
    'assertionTreeRoot', 'challengeCsvBlocks', 'recoveryCsvBlocks'
) 'blue.honestTranscript.graphVerification'
Assert-String $honestTranscript.graph 'graphHash' $honestReceipt.graphHash 'blue.honestTranscript.graph'
Assert-Boolean $honestTranscript.graphVerification 'ok' $true 'blue.honestTranscript.graphVerification'
Assert-String $honestTranscript.verifierAttestation 'artifactBundleSha256' `
    $honestReceipt.artifactBundleSha256 'blue.honestTranscript.verifierAttestation'
Assert-String $honestTranscript.verifierAttestation 'verifierKeyId' `
    $blue.policy.factProviderKeyId 'blue.honestTranscript.verifierAttestation'
Assert-String $honestTranscript.verifierAttestation 'policyHash' `
    $blue.policy.policyHash 'blue.honestTranscript.verifierAttestation'
Assert-String $honestTranscript.verifierAttestation 'network' `
    $blue.policyCore.network 'blue.honestTranscript.verifierAttestation'
Assert-String $honestTranscript.verifierAttestation 'caseId' `
    'honest_true' 'blue.honestTranscript.verifierAttestation'
Assert-String $honestTranscript.verifierAttestation 'requestNonce' `
    $honestReceipt.requestNonce 'blue.honestTranscript.verifierAttestation'

$artifactMaterial = $honestTranscript.artifactMaterial
$artifactBundle = $honestTranscript.artifactBundle
Assert-String $artifactMaterial 'kind' 'bark_bitvm_verifier_artifact_bytes_v1' `
    'blue.honestTranscript.artifactMaterial'
Assert-String $artifactBundle 'kind' 'bark_bitvm_verifier_artifacts_v1' `
    'blue.honestTranscript.artifactBundle'
foreach ($binding in @(
    [pscustomobject]@{ Material = 'claimInputBase64'; Bundle = 'claimInputSha256' },
    [pscustomobject]@{ Material = 'proofArtifactBase64'; Bundle = 'proofArtifactSha256' },
    [pscustomobject]@{ Material = 'shinigamiArtifactBase64'; Bundle = 'shinigamiArtifactSha256' }
)) {
    $derivedSha256 = Get-Base64Sha256 $artifactMaterial $binding.Material `
        'blue.honestTranscript.artifactMaterial'
    Assert-String $artifactBundle $binding.Bundle $derivedSha256 `
        'blue.honestTranscript.artifactBundle'
}

$boundary = $blue.securityBoundary
Assert-ExactPropertySet $boundary @(
    'model', 'recomputedFactsOverrideOperatorDisclosures', 'challengerPrivateKeyExposed',
    'bitcoinVerifiesBip340SettlementCosignature', 'bitcoinVerifiesStwo',
    'bitcoinVerifiesShinigami', 'allOnesLieHasBitvmDisprove',
    'allOnesLieBlockedBeforeFunding', 'emergencyRecoveryStillExistsAfterLongCsv',
    'notTrustlessZkEnforcement', 'fundedOrBroadcast', 'syntheticAssertionOutpoint',
    'sameProcessTestDouble', 'operatorSecretPassedIntoCosignerClosure',
    'nonCustodialSignerSeparationDemonstrated', 'fullCanonicalClaimDigestPinned',
    'linearBindingCollisionsBlockedBeforeFunding',
    'factsSelectedBySignedArtifactAttestation', 'operatorCaseLabelSelectsFacts', 'note'
    'artifactHashesDerivedFromSuppliedBytes', 'artifactBytesAreSyntheticTestDouble',
    'attestationBoundToPolicyCaseAndNonce', 'actualStwoShinigamiExecutionInsideVerifier',
    'artifactBytesLoadedFromTrustedStorage', 'attestationNonceConsumptionPersisted'
) 'blue.securityBoundary'
Assert-String $boundary 'model' 'independent-trusted-verifier-and-bitcoin-settlement-cosigner' 'blue.securityBoundary'
foreach ($name in @(
    'recomputedFactsOverrideOperatorDisclosures', 'bitcoinVerifiesBip340SettlementCosignature',
    'allOnesLieBlockedBeforeFunding', 'emergencyRecoveryStillExistsAfterLongCsv',
    'notTrustlessZkEnforcement', 'syntheticAssertionOutpoint',
    'sameProcessTestDouble', 'operatorSecretPassedIntoCosignerClosure',
    'fullCanonicalClaimDigestPinned', 'linearBindingCollisionsBlockedBeforeFunding',
    'factsSelectedBySignedArtifactAttestation', 'artifactHashesDerivedFromSuppliedBytes',
    'artifactBytesAreSyntheticTestDouble', 'attestationBoundToPolicyCaseAndNonce'
)) {
    Assert-Boolean $boundary $name $true 'blue.securityBoundary'
}
foreach ($name in @(
    'challengerPrivateKeyExposed', 'bitcoinVerifiesStwo', 'bitcoinVerifiesShinigami',
    'allOnesLieHasBitvmDisprove', 'fundedOrBroadcast',
    'nonCustodialSignerSeparationDemonstrated', 'operatorCaseLabelSelectsFacts',
    'actualStwoShinigamiExecutionInsideVerifier', 'artifactBytesLoadedFromTrustedStorage',
    'attestationNonceConsumptionPersisted'
)) {
    Assert-Boolean $boundary $name $false 'blue.securityBoundary'
}

$ExpectedMatrixIds = @(
    'honest-independent-facts',
    'generic-linear-binding-collision-substitution',
    'bark-linear-binding-collision-substitution',
    'generic-settlement-limb-collision-substitution',
    'bark-settlement-limb-collision-substitution',
    'dishonest-operator-false-all-ones',
    'false-artifact-relabelled-as-honest-case',
    'false-artifact-bytes-with-claimed-honest-hashes',
    'false-fact-disclosed-as-zero',
    'rogue-challenger-key-substitution',
    'self-allowlisted-state-signer',
    'internally-valid-policy-substitution'
)
$ExpectedMatrixSchemas = @{
    'honest-independent-facts' = @(
        'attack', 'externalTruth', 'operatorDisclosedAllOnes', 'publicTraceValid',
        'bitvmDisproveConstructible', 'trustedCosignatureIssued',
        'utxorefGraphVerified', 'fundingAuthorized', 'caught', 'passed'
    )
    'generic-linear-binding-collision-substitution' = @(
        'attack', 'linearBindingUnchanged', 'fullClaimDigestMatched',
        'publicTraceValid', 'bitvmDisproveConstructible', 'reason',
        'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
    'bark-linear-binding-collision-substitution' = @(
        'attack', 'linearBindingUnchanged', 'fullClaimDigestMatched',
        'publicTraceValid', 'bitvmDisproveConstructible', 'reason',
        'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
    'generic-settlement-limb-collision-substitution' = @(
        'attack', 'linearBindingUnchanged', 'fullClaimDigestMatched',
        'publicTraceValid', 'bitvmDisproveConstructible', 'reason',
        'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
    'bark-settlement-limb-collision-substitution' = @(
        'attack', 'linearBindingUnchanged', 'fullClaimDigestMatched',
        'publicTraceValid', 'bitvmDisproveConstructible', 'reason',
        'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
    'dishonest-operator-false-all-ones' = @(
        'attack', 'externalTruth', 'operatorDisclosedAllOnes', 'publicTraceValid',
        'bitvmDisproveConstructible', 'caughtBy', 'reason',
        'trustedCosignatureIssued', 'utxorefGraphVerificationStatus',
        'fundingAuthorized', 'caught', 'passed'
    )
    'false-artifact-relabelled-as-honest-case' = @(
        'attack', 'proposalCaseId', 'attestedStwoVerified', 'publicTraceValid',
        'bitvmDisproveConstructible', 'reason', 'trustedCosignatureIssued',
        'utxorefGraphVerificationStatus', 'fundingAuthorized', 'caught', 'passed'
    )
    'false-artifact-bytes-with-claimed-honest-hashes' = @(
        'attack', 'proposalCaseId', 'claimedBundleSha256', 'derivedBundleSha256',
        'claimedHashesMatchSuppliedBytes', 'utxorefGraphVerificationStatus', 'reason',
        'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
    'false-fact-disclosed-as-zero' = @(
        'attack', 'externalTruth', 'operatorDisclosedAllOnes', 'publicTraceValid',
        'bitvmDisproveConstructible', 'caughtBy', 'reason',
        'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
    'rogue-challenger-key-substitution' = @(
        'attack', 'rogueGraphCouldBeSelfVerified', 'reason',
        'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
    'self-allowlisted-state-signer' = @(
        'attack', 'rogueGraphSelfTrustVerified', 'fixedPolicyVerificationPassed',
        'fixedPolicyReason', 'reason', 'trustedCosignatureIssued',
        'fundingAuthorized', 'caught', 'passed'
    )
    'internally-valid-policy-substitution' = @(
        'attack', 'proposedPolicySelfHashValid', 'matchesPinnedFundingPolicy',
        'reason', 'trustedCosignatureIssued', 'fundingAuthorized', 'caught', 'passed'
    )
}
$matrix = @($blue.matrix)
if ($matrix.Count -ne $ExpectedMatrixIds.Count) {
    throw 'Blue team did not emit exactly twelve matrix rows'
}
$matrixById = @{}
foreach ($row in $matrix) {
    $id = Get-RequiredProperty $row 'attack' 'blue.matrix.row'
    if ($id -isnot [string] -or $id -notin $ExpectedMatrixIds -or $matrixById.ContainsKey($id)) {
        throw "Unexpected or duplicate blue-team matrix row: $id"
    }
    Assert-ExactPropertySet $row $ExpectedMatrixSchemas[$id] "blue.matrix[$id]"
    $matrixById[$id] = $row
    Assert-Boolean $row 'passed' $true "blue.matrix[$id]"
}
foreach ($id in $ExpectedMatrixIds) {
    if (-not $matrixById.ContainsKey($id)) {
        throw "Missing blue-team matrix row: $id"
    }
}

$honest = $matrixById['honest-independent-facts']
Assert-Boolean $honest 'externalTruth' $true 'blue.matrix[honest]'
Assert-Boolean $honest 'publicTraceValid' $true 'blue.matrix[honest]'
Assert-Boolean $honest 'bitvmDisproveConstructible' $false 'blue.matrix[honest]'
Assert-Boolean $honest 'trustedCosignatureIssued' $true 'blue.matrix[honest]'
Assert-Boolean $honest 'utxorefGraphVerified' $true 'blue.matrix[honest]'
Assert-Boolean $honest 'fundingAuthorized' $true 'blue.matrix[honest]'
Assert-Boolean $honest 'caught' $false 'blue.matrix[honest]'

foreach ($id in @(
    'generic-linear-binding-collision-substitution',
    'bark-linear-binding-collision-substitution',
    'generic-settlement-limb-collision-substitution',
    'bark-settlement-limb-collision-substitution'
)) {
    $collisionRow = $matrixById[$id]
    Assert-Boolean $collisionRow 'linearBindingUnchanged' $true "blue.matrix[$id]"
    Assert-Boolean $collisionRow 'fullClaimDigestMatched' $false "blue.matrix[$id]"
    Assert-Boolean $collisionRow 'publicTraceValid' $true "blue.matrix[$id]"
    Assert-Boolean $collisionRow 'bitvmDisproveConstructible' $false "blue.matrix[$id]"
    Assert-String $collisionRow 'reason' `
        'full canonical claim-input digest substitution rejected' `
        "blue.matrix[$id]"
}

$lie = $matrixById['dishonest-operator-false-all-ones']
Assert-Boolean $lie 'externalTruth' $false 'blue.matrix[all-ones-lie]'
Assert-Boolean $lie 'publicTraceValid' $true 'blue.matrix[all-ones-lie]'
Assert-Boolean $lie 'bitvmDisproveConstructible' $false 'blue.matrix[all-ones-lie]'
Assert-Boolean $lie 'trustedCosignatureIssued' $false 'blue.matrix[all-ones-lie]'
Assert-String $lie 'utxorefGraphVerificationStatus' 'not-attempted' 'blue.matrix[all-ones-lie]'
Assert-Boolean $lie 'fundingAuthorized' $false 'blue.matrix[all-ones-lie]'
Assert-Boolean $lie 'caught' $true 'blue.matrix[all-ones-lie]'
Assert-String $lie 'reason' 'operator disclosures differ from independent recomputation' 'blue.matrix[all-ones-lie]'

$relabel = $matrixById['false-artifact-relabelled-as-honest-case']
Assert-String $relabel 'proposalCaseId' 'honest_true' 'blue.matrix[relabel]'
Assert-Boolean $relabel 'attestedStwoVerified' $false 'blue.matrix[relabel]'
Assert-Boolean $relabel 'publicTraceValid' $true 'blue.matrix[relabel]'
Assert-Boolean $relabel 'bitvmDisproveConstructible' $false 'blue.matrix[relabel]'
Assert-String $relabel 'utxorefGraphVerificationStatus' 'not-attempted' 'blue.matrix[relabel]'
Assert-String $relabel 'reason' 'operator disclosures differ from independent recomputation' 'blue.matrix[relabel]'

$falseBytes = $matrixById['false-artifact-bytes-with-claimed-honest-hashes']
Assert-String $falseBytes 'proposalCaseId' 'honest_true' 'blue.matrix[false-bytes]'
Assert-Hex64 $falseBytes 'claimedBundleSha256' 'blue.matrix[false-bytes]'
Assert-Hex64 $falseBytes 'derivedBundleSha256' 'blue.matrix[false-bytes]'
if ($falseBytes.claimedBundleSha256 -ceq $falseBytes.derivedBundleSha256) {
    throw 'False artifact bytes unexpectedly matched the claimed honest bundle'
}
Assert-Boolean $falseBytes 'claimedHashesMatchSuppliedBytes' $false 'blue.matrix[false-bytes]'
Assert-String $falseBytes 'utxorefGraphVerificationStatus' 'not-attempted' 'blue.matrix[false-bytes]'
Assert-String $falseBytes 'reason' `
    'claimed artifact hashes do not match supplied artifact bytes' 'blue.matrix[false-bytes]'

$disclosedZero = $matrixById['false-fact-disclosed-as-zero']
Assert-Boolean $disclosedZero 'publicTraceValid' $true 'blue.matrix[disclosed-zero]'
Assert-Boolean $disclosedZero 'bitvmDisproveConstructible' $true 'blue.matrix[disclosed-zero]'
Assert-Boolean $disclosedZero 'trustedCosignatureIssued' $false 'blue.matrix[disclosed-zero]'
Assert-Boolean $disclosedZero 'fundingAuthorized' $false 'blue.matrix[disclosed-zero]'
Assert-Boolean $disclosedZero 'caught' $true 'blue.matrix[disclosed-zero]'

$rogueKey = $matrixById['rogue-challenger-key-substitution']
Assert-Boolean $rogueKey 'rogueGraphCouldBeSelfVerified' $true 'blue.matrix[rogue-key]'
$rogueSigner = $matrixById['self-allowlisted-state-signer']
Assert-Boolean $rogueSigner 'rogueGraphSelfTrustVerified' $true 'blue.matrix[rogue-signer]'
Assert-Boolean $rogueSigner 'fixedPolicyVerificationPassed' $false 'blue.matrix[rogue-signer]'
$policySubstitution = $matrixById['internally-valid-policy-substitution']
Assert-Boolean $policySubstitution 'proposedPolicySelfHashValid' $true 'blue.matrix[policy-substitution]'
Assert-Boolean $policySubstitution 'matchesPinnedFundingPolicy' $false 'blue.matrix[policy-substitution]'

foreach ($id in $ExpectedMatrixIds | Where-Object { $_ -ne 'honest-independent-facts' }) {
    $row = $matrixById[$id]
    Assert-Boolean $row 'caught' $true "blue.matrix[$id]"
    Assert-Boolean $row 'trustedCosignatureIssued' $false "blue.matrix[$id]"
    Assert-Boolean $row 'fundingAuthorized' $false "blue.matrix[$id]"
}

$BlueAuditPath = Join-Path $OutputDir 'blue-evidence-audit.json'
$blueAudit = Invoke-JsonHarness -Script $AuditScript -Destination $BlueAuditPath -InputJson $BluePath
Assert-ExactPropertySet $blueAudit @(
    'schema', 'utxorefSourceClosureVerified', 'policyHashVerified', 'artifactBytesRehashed',
    'artifactBundleDigestVerified', 'attestationSignatureVerified',
    'attestationContextVerified', 'attestationDigestVerified',
    'allTrueFactsVerified', 'attestationStateCrossLinkVerified',
    'stateSignerKeyVerified', 'utxorefGraphVerified', 'fraudCount', 'graphHash'
) 'blueAudit'
Assert-String $blueAudit 'schema' 'bark-bitvm-blue-evidence-independent-audit-v1' 'blueAudit'
foreach ($name in @(
    'utxorefSourceClosureVerified', 'policyHashVerified', 'artifactBytesRehashed',
    'artifactBundleDigestVerified',
    'attestationSignatureVerified', 'attestationContextVerified',
    'attestationDigestVerified', 'allTrueFactsVerified',
    'attestationStateCrossLinkVerified', 'stateSignerKeyVerified', 'utxorefGraphVerified'
)) {
    Assert-Boolean $blueAudit $name $true 'blueAudit'
}
Assert-Integer $blueAudit 'fraudCount' 0 'blueAudit'
Assert-String $blueAudit 'graphHash' $honestReceipt.graphHash 'blueAudit'

$serializedRed = Get-Content -Raw -LiteralPath $RedPath
$serializedBlue = Get-Content -Raw -LiteralPath $BluePath
if ($serializedRed -match '-----BEGIN [^-]*PRIVATE KEY-----' -or
    $serializedBlue -match '-----BEGIN [^-]*PRIVATE KEY-----') {
    throw 'Red/blue evidence contains private-key PEM material'
}

$RedEvidenceSha256 = (Get-FileHash -LiteralPath $RedPath -Algorithm SHA256).Hash.ToLowerInvariant()
$BlueEvidenceSha256 = (Get-FileHash -LiteralPath $BluePath -Algorithm SHA256).Hash.ToLowerInvariant()
$BlueAuditSha256 = (Get-FileHash -LiteralPath $BlueAuditPath -Algorithm SHA256).Hash.ToLowerInvariant()

$summary = [ordered]@{
    schema = 'bark-bitvm-red-blue-run-v1'
    verdict = 'dishonest operator reproduced, then blocked by pinned independent cosigner policy'
    utxorefCommit = $ExpectedUtxoRefCommit
    red = [ordered]@{
        graphChecks = 1
        falseAllOnesGraphHash = $falseAllOnes.graph_hash
        collisionVectors = $collisions.Count
    }
    blue = [ordered]@{
        totalRows = $matrix.Count
        honestControls = 1
        attackRows = 11
        caughtAttacks = 11
        passedRows = 12
    }
    securityBoundary = 'trusted cosigner test double; not trustless ZK enforcement'
    sourceProvenance = [ordered]@{
        redScriptSha256 = $RedScriptSha256
        blueScriptSha256 = $BlueScriptSha256
        auditScriptSha256 = $AuditScriptSha256
        runnerSha256 = $RunnerSha256
        nodeVersion = $NodeVersion
        gitVersion = $GitVersion
        powershellVersion = $PowerShellVersion
    }
    artifacts = [ordered]@{
        redTeam = 'red-team.json'
        blueTeam = 'blue-team.json'
        blueAudit = 'blue-evidence-audit.json'
        redTeamSha256 = $RedEvidenceSha256
        blueTeamSha256 = $BlueEvidenceSha256
        blueAuditSha256 = $BlueAuditSha256
    }
}
$SummaryPath = Join-Path $OutputDir 'summary.json'
[IO.File]::WriteAllText($SummaryPath, ($summary | ConvertTo-Json -Depth 8) + "`n")

Write-Host 'Red/blue harness passed: false-all-ones exploit + 4/4 collisions reproduced; 12/12 blue gates passed.'
Write-Host "Summary: $SummaryPath"
