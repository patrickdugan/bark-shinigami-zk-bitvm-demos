<#
LEGACY TEST-DOUBLE HARNESS ONLY.
This runs the old linear Cairo relation and UTXORef trusted-cosigner model. It
must not be used as evidence of BarkSpendEnvelopeV1 or ZK-BitVM enforcement.
#>

param(
    [string] $ShinigamiRepo = 'D:\_external\shinigami',
    [string] $ShinigamiScarb = 'D:\_tools\scarb-v2.9.2\scarb-v2.9.2-x86_64-pc-windows-msvc\bin\scarb.exe',
    [string] $StwoVerifier = 'D:\cargo-target\stwo-cairo-prover\debug\verify.exe',
    [string] $CairoExecutable = 'D:\cargo-target\ark-shinigami\dev\ark_vtxo_prover.executable.json',
    [string] $ProofDir = 'D:\cargo-target\ark-shinigami\proofs',
    [string] $UtxoRefRepo = 'C:\projects\UTXORef\UTXO-Ref',
    [string] $TargetRoot = '',
    [string] $OutputDir = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$ShowcaseRoot = (Resolve-Path $PSScriptRoot).Path
$BarkRepo = (Resolve-Path (Join-Path $ShowcaseRoot '..\..\bark-pr')).Path
$CargoManifest = Join-Path $ShowcaseRoot 'Cargo.toml'
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
    $OutputDir = Join-Path $TargetRoot "runs\$runId"
}
$OutputDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$CargoTarget = Join-Path $TargetRoot 'cargo'
New-Item -ItemType Directory -Force -Path $CargoTarget | Out-Null

foreach ($required in @(
    $ShinigamiRepo, $ShinigamiScarb, $StwoVerifier, $CairoExecutable,
    $ProofDir, $UtxoRefRepo, $BarkRepo, $CargoManifest
)) {
    if (-not (Test-Path $required)) {
        throw "Missing demo prerequisite: $required"
    }
}

foreach ($command in @('git', 'node', 'cargo')) {
    if ($null -eq (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "$command is required for the composed demo runner"
    }
}

$ExpectedBarkCommit = '0ff3636b459c6b0687e9e09eb3024b09975e0b19'
$ExpectedShinigamiCommit = '7e8c05d60b4bd7ae91ddc18a42e8e13090286f0c'
$ExpectedUtxoRefCommit = '13f43d7f7bbddf10fa507770645ef05e49189441'
$ExpectedScarbSha256 = 'e86974d48a6aa25403f69e1eae3dfe1d6ece7f12a8e5de6f7a2eb3d96f76bd71'
$ExpectedVerifierSha256 = '4b3dc11dffd8bda4481d662cef7e4778393588935dc8fcf9d4e4ee154c06850b'
$ExpectedExecutableSha256 = 'cb7d5111087d1defd85eaf6aaaf3b5442a286fc16391df014dedc9283faa9bfa'
$ExpectedOwnerProofSha256 = 'd11bf6d8624efde5b9023da9b228385b52e6f2f02b3e110a1dc80fc0b7f5054b'
$ExpectedCetProofSha256 = 'a39afc7e1577f0f5eb6514539778845401f04b0459201029e04244e1eefdedea'

$Cases = @(
    [pscustomobject]@{
        Id = 'owner_exit_allow'
        Example = 'owner_exit_allow'
        ProofFile = 'ark_zk_miniscript_owner_csv_exit.proof.json'
        ExpectedAuthorization = $true
    },
    [pscustomobject]@{
        Id = 'owner_exit_challenge'
        Example = 'owner_exit_challenge'
        ProofFile = 'ark_zk_miniscript_owner_csv_exit.proof.json'
        ExpectedAuthorization = $false
    },
    [pscustomobject]@{
        Id = 'virtual_cet_guard'
        Example = 'virtual_cet_guard'
        ProofFile = 'ark_zk_miniscript_dlc_virtual_cet_settlement.proof.json'
        ExpectedAuthorization = $true
    }
)

foreach ($relative in @(
    'Cargo.toml', 'Cargo.lock', 'bitcoin-ext\Cargo.toml',
    'lib\Cargo.toml', 'shinigami\Cargo.toml'
)) {
    if (-not (Test-Path -LiteralPath (Join-Path $BarkRepo $relative))) {
        throw "Pinned Bark dependency closure is missing $relative"
    }
}
$ActualBarkCommit = (& git -C $BarkRepo rev-parse HEAD).Trim()
$BarkDependencyStatus = (& git -C $BarkRepo status --porcelain -- `
    Cargo.toml Cargo.lock bitcoin-ext lib shinigami) -join "`n"
if ($LASTEXITCODE -ne 0 -or $ActualBarkCommit -ne $ExpectedBarkCommit -or $BarkDependencyStatus) {
    throw 'The active Bark path-dependency closure is not clean and exactly pinned'
}

& git -C $ShinigamiRepo cat-file -e "$ExpectedShinigamiCommit`^{commit}"
if ($LASTEXITCODE -ne 0) {
    throw "Shinigami object source does not contain $ExpectedShinigamiCommit"
}
& git -C $UtxoRefRepo cat-file -e "$ExpectedUtxoRefCommit`^{commit}"
if ($LASTEXITCODE -ne 0) {
    throw "UTXORef source checkout does not contain $ExpectedUtxoRefCommit"
}

foreach ($pin in @(
    [pscustomobject]@{ Path = $ShinigamiScarb; Hash = $ExpectedScarbSha256; Label = 'Scarb' },
    [pscustomobject]@{ Path = $StwoVerifier; Hash = $ExpectedVerifierSha256; Label = 'STWO verifier' },
    [pscustomobject]@{ Path = $CairoExecutable; Hash = $ExpectedExecutableSha256; Label = 'Cairo executable' },
    [pscustomobject]@{
        Path = Join-Path $ProofDir 'ark_zk_miniscript_owner_csv_exit.proof.json'
        Hash = $ExpectedOwnerProofSha256
        Label = 'owner-exit proof'
    },
    [pscustomobject]@{
        Path = Join-Path $ProofDir 'ark_zk_miniscript_dlc_virtual_cet_settlement.proof.json'
        Hash = $ExpectedCetProofSha256
        Label = 'virtual-CET proof'
    }
)) {
    if (-not (Test-Path -LiteralPath $pin.Path)) {
        throw "Missing $($pin.Label): $($pin.Path)"
    }
    $actual = (Get-FileHash $pin.Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $pin.Hash) {
        throw "$($pin.Label) hash $actual does not match $($pin.Hash)"
    }
}

# Use the caller's repository only as an object source. This prevents its active
# branch, untracked files, or concurrent worktree changes from affecting Scarb.
$PinnedShinigamiRepo = Join-Path $OutputDir 'shinigami-pinned'
& git clone --quiet --shared --no-checkout $ShinigamiRepo $PinnedShinigamiRepo
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to create the isolated Shinigami clone'
}
& git -C $PinnedShinigamiRepo config core.autocrlf false
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to disable line-ending conversion in the Shinigami clone'
}
& git -C $PinnedShinigamiRepo checkout --quiet --detach $ExpectedShinigamiCommit
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to check out the pinned Shinigami commit'
}
$ActualShinigamiCommit = (& git -C $PinnedShinigamiRepo rev-parse HEAD).Trim()
$ShinigamiStatus = (& git -C $PinnedShinigamiRepo status --porcelain) -join "`n"
if ($LASTEXITCODE -ne 0 -or $ActualShinigamiCommit -ne $ExpectedShinigamiCommit -or $ShinigamiStatus) {
    throw 'The isolated Shinigami checkout is not clean and exactly pinned'
}

# A unique target makes every Shinigami artifact source-built for this run.
$ShinigamiTarget = Join-Path $OutputDir "shinigami-target-$([Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $ShinigamiTarget | Out-Null
$priorTarget = $env:SCARB_TARGET_DIR
$env:SCARB_TARGET_DIR = $ShinigamiTarget
Push-Location $PinnedShinigamiRepo
try {
    & $ShinigamiScarb --offline build --package shinigami_cmds
    if ($LASTEXITCODE -ne 0) {
        throw 'Fresh pinned Shinigami build failed'
    }
} finally {
    Pop-Location
    $env:SCARB_TARGET_DIR = $priorTarget
}

# The source checkout may be active or dirty. Build an isolated sparse clone at
# the reviewed commit so later local branch movement cannot change required JS.
$PinnedUtxoRefRepo = Join-Path $OutputDir "utxoref-$([Guid]::NewGuid().ToString('N'))"
& git clone --quiet --shared --no-checkout $UtxoRefRepo $PinnedUtxoRefRepo
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to create isolated UTXORef clone'
}
& git -C $PinnedUtxoRefRepo config core.autocrlf false
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to disable line-ending conversion in the UTXORef clone'
}
& git -C $PinnedUtxoRefRepo sparse-checkout init --cone
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to initialize the isolated UTXORef sparse checkout'
}
& git -C $PinnedUtxoRefRepo sparse-checkout set bitvm3/utxo_referee
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to select the reviewed UTXORef dependency closure'
}
& git -C $PinnedUtxoRefRepo checkout --quiet --detach $ExpectedUtxoRefCommit
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to check out pinned UTXORef commit'
}
$ActualUtxoRefCommit = (& git -C $PinnedUtxoRefRepo rev-parse HEAD).Trim()
$UtxoRefStatus = (& git -C $PinnedUtxoRefRepo status --porcelain) -join "`n"
if ($LASTEXITCODE -ne 0 -or $ActualUtxoRefCommit -ne $ExpectedUtxoRefCommit -or $UtxoRefStatus) {
    throw 'The isolated UTXORef checkout is not clean and exactly pinned'
}

$Summary = [Collections.Generic.List[object]]::new()
foreach ($case in $Cases) {
    Write-Host "=== $($case.Id) ==="
    $proofPath = Join-Path $ProofDir $case.ProofFile
    if (-not (Test-Path $proofPath)) {
        throw "Missing proof for $($case.Id): $proofPath"
    }

    $receiptPath = Join-Path $OutputDir "$($case.Id).receipt.json"
    $priorCargoTarget = $env:CARGO_TARGET_DIR
    $env:CARGO_TARGET_DIR = $CargoTarget
    try {
        $receiptJson = & cargo run --manifest-path $CargoManifest --locked --bin $case.Example --quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Bark demo emitter failed for $($case.Id)"
        }
    } finally {
        $env:CARGO_TARGET_DIR = $priorCargoTarget
    }
    [IO.File]::WriteAllText($receiptPath, ($receiptJson -join "`n") + "`n")

    $bitvmPath = Join-Path $OutputDir "$($case.Id).bitvm.json"
    & node (Join-Path $PSScriptRoot 'bitvm-assertion.js') `
        --receipt $receiptPath `
        --output $bitvmPath `
        --proof $proofPath `
        --cairo-executable $CairoExecutable `
        --stwo-verifier $StwoVerifier `
        --shinigami-repo $PinnedShinigamiRepo `
        --shinigami-scarb $ShinigamiScarb `
        --shinigami-target $ShinigamiTarget `
        --utxoref-repo $PinnedUtxoRefRepo
    if ($LASTEXITCODE -ne 0) {
        throw "Composed verifier/BitVM demo failed for $($case.Id)"
    }

    $report = Get-Content -Raw $bitvmPath | ConvertFrom-Json
    $receiptFileSha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($report.receipt_hash_semantics -cne 'raw-file-bytes' -or
        $report.receipt_sha256 -cne $receiptFileSha256) {
        throw "BitVM report did not bind the raw receipt bytes for $($case.Id)"
    }
    if ([bool]$report.trace.authorization_assertion -ne $case.ExpectedAuthorization) {
        throw "Unexpected authorization assertion for $($case.Id)"
    }
    if ($case.ExpectedAuthorization -and $null -ne $report.disprove) {
        throw "Honest case $($case.Id) unexpectedly emitted a disprove transaction"
    }
    if (-not $case.ExpectedAuthorization -and -not [bool]$report.disprove.verified) {
        throw "Challenge case $($case.Id) did not emit a verified disprove transaction"
    }
    $Summary.Add([pscustomobject]@{
        caseId = $case.Id
        claimBindingMatches = [bool]$report.checks.claim_binding_matches_stwo_output
        stwoVerified = [bool]$report.checks.stwo.freshlyVerified
        shinigamiVerified = [bool]$report.checks.shinigami.verified
        authorizationAssertion = [bool]$report.trace.authorization_assertion
        disproveVerified = if ($null -eq $report.disprove) { $null } else { [bool]$report.disprove.verified }
        graphHash = $report.assertion.graph_hash
        receiptFile = Split-Path -Leaf $receiptPath
        receiptSha256 = $receiptFileSha256
        bitvmFile = Split-Path -Leaf $bitvmPath
        bitvmSha256 = (Get-FileHash -LiteralPath $bitvmPath -Algorithm SHA256).Hash.ToLowerInvariant()
    })
}

# Cargo path dependencies cannot be detached without changing the showcase
# lockfile. Recheck the reviewed closure after all emitters to detect movement
# during the run; callers must still avoid concurrent edits while it executes.
$FinalBarkCommit = (& git -C $BarkRepo rev-parse HEAD).Trim()
$FinalBarkDependencyStatus = (& git -C $BarkRepo status --porcelain -- `
    Cargo.toml Cargo.lock bitcoin-ext lib shinigami) -join "`n"
if ($LASTEXITCODE -ne 0 -or $FinalBarkCommit -ne $ExpectedBarkCommit -or $FinalBarkDependencyStatus) {
    throw 'The Bark path-dependency closure moved or became dirty during the run'
}

$summaryPath = Join-Path $OutputDir 'summary.json'
[IO.File]::WriteAllText($summaryPath, ($Summary | ConvertTo-Json -Depth 5) + "`n")
Write-Host "All three composed demos passed. Summary: $summaryPath"
