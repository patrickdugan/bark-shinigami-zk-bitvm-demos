param(
    [string] $Scarb = 'scarb',
    [string] $CargoTargetDir = 'D:\cargo-target\bark-bitvm-showcase',
    [string] $ScarbCacheDir = 'D:\cargo-target\scarb-cache-2.18',
    [string] $ScarbTargetDir = 'D:\cargo-target\bark-shinigami-cairo-2.18'
)

$ErrorActionPreference = 'Stop'
$env:CARGO_TARGET_DIR = $CargoTargetDir
$env:SCARB_CACHE = $ScarbCacheDir
$env:SCARB_TARGET_DIR = $ScarbTargetDir
$env:PYTHONPATH = (Resolve-Path (Join-Path $PSScriptRoot 'tools')).Path
$python = Join-Path $PSScriptRoot '.python310\python.exe'

function New-CairoArguments {
    param([string] $Name, [string] $Mutation, [switch] $AllowInvalid)
    $base = Join-Path $PSScriptRoot "artifacts\red-$Name.base.arguments.json"
    $args = Join-Path $PSScriptRoot "artifacts\red-$Name.arguments.json"
    & cargo run --quiet --bin cairo_fixture -- owner_exit_allow $base $Mutation | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "fixture generation failed for $Name" }
    $witness = $base -replace '\.json$', '.witness-input.json'
    $generator = Join-Path $PSScriptRoot 'generate-garaga-arguments.py'
    $extra = if ($AllowInvalid) { @('--test-only-allow-invalid') } else { @() }
    & $python $generator $witness $args $extra | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Garaga argument generation failed for $Name" }
    return $args
}

function Invoke-Cairo {
    param([string] $Arguments)
    Push-Location (Join-Path $PSScriptRoot 'cairo-shinigami')
    try {
        $output = (& $Scarb execute --no-build --arguments-file $Arguments --print-program-output 2>&1 | Out-String)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    } finally {
        Pop-Location
    }
}

$falseHeights = Invoke-Cairo (New-CairoArguments 'false-heights' 'false_heights')
if ($falseHeights.ExitCode -ne 0 -or $falseHeights.Output -notmatch '(?s)Program output:\s*1\s+0\s+0') {
    throw "false heights did not remain fail-closed: $($falseHeights.Output)"
}

$falseImage = Invoke-Cairo (New-CairoArguments 'false-image' 'false_risc0_pin')
if ($falseImage.ExitCode -eq 0 -or $falseImage.Output -notmatch 'RISC0 image unavailable') {
    throw "attacker RISC Zero image was not rejected: $($falseImage.Output)"
}

$phantomAmount = Invoke-Cairo (New-CairoArguments 'phantom-amount' 'phantom_prevout_amount' -AllowInvalid)
if ($phantomAmount.ExitCode -eq 0 -or $phantomAmount.Output -notmatch 'unexpected Bark prevout amount') {
    throw "phantom prevout amount was not rejected: $($phantomAmount.Output)"
}

[pscustomobject]@{
    schema = 'bark-shinigami-cairo-adversarial-v1'
    falseHeights = 'relation_valid_but_chain_and_authorization_zero'
    attackerRisc0Image = 'rejected'
    phantomPrevoutAmount = 'rejected'
    operatorTakeAuthorized = $false
} | ConvertTo-Json
