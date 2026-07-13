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
    $output = (& $Scarb build 2>&1 | Out-String)
    $status = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($status -eq 0) {
    throw 'Cairo executable unexpectedly built; review the syscall gate before enabling any proof'
}
if ($output -notmatch 'sha256_process_block_syscall' -or
    $output -notmatch 'Syscalls are not supported') {
    throw "Cairo failed for an unreviewed reason:`n$output"
}

[pscustomobject]@{
    schema = 'bark-shinigami-cairo-tapout-v1'
    gate = 'stwo-cairo-executable'
    status = 'blocked'
    reason = 'Shinigami SHA-256 lowers to sha256_process_block_syscall, which Cairo executables reject'
    operatorTakeAuthorized = $false
} | ConvertTo-Json
