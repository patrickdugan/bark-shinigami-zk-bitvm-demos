param(
    [string] $Scarb = 'scarb',
    [string] $CacheDir = 'D:\cargo-target\scarb-cache-2.18',
    [string] $TargetDir = 'D:\cargo-target\bark-shinigami-cairo-2.18'
)

$ErrorActionPreference = 'Stop'
$env:SCARB_CACHE = $CacheDir
$env:SCARB_TARGET_DIR = $TargetDir
New-Item -ItemType Directory -Force -Path $CacheDir, $TargetDir | Out-Null

Push-Location (Join-Path $PSScriptRoot 'cairo-shinigami')
try {
    & $Scarb fmt --check
    if ($LASTEXITCODE -ne 0) { throw 'Cairo formatting gate failed' }
    & $Scarb build
    if ($LASTEXITCODE -ne 0) { throw 'STWO-compatible Cairo executable build failed' }
} finally {
    Pop-Location
}

$executable = Join-Path $TargetDir 'dev\bark_shinigami_relation.executable.json'
if (-not (Test-Path -LiteralPath $executable)) {
    throw "Expected Cairo executable was not produced: $executable"
}

[pscustomobject]@{
    schema = 'bark-shinigami-cairo-build-v2'
    gate = 'stwo-cairo-executable'
    status = 'ready_for_proving'
    executable = $executable
    executableSha256 = (Get-FileHash $executable -Algorithm SHA256).Hash.ToLowerInvariant()
    operatorTakeAuthorized = $false
    nextGate = 'verified STWO proof plus recursive outer proof and relay-tested BitVM graph'
} | ConvertTo-Json
