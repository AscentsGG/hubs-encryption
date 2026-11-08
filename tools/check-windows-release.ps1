# Checks the Hubs for Windows release thehubs.gg serves now against this repository.
#
#   pwsh tools/check-windows-release.ps1            the current release
#   pwsh tools/check-windows-release.ps1 0.3.51     a given version
#
# 1. Reads the release from thehubs.gg's catalog, and its signed statement from
#    github.com/AscentsGG/hubs-releases (apps/windows/<version>.json).
# 2. Verifies the statement's signature with tools/release-signing-key.pem.
# 3. Builds the encryption library at the commit the statement names, with
#    that commit's rust/hubs-mls-ffi/build-reproducible.ps1.
# 4. Downloads the release, checks its SHA-256 against the statement, and
#    compares the library inside it with the rebuild (compare-dll.py), then
#    checks the Authenticode digest is the one the statement names.
#
# Needs a Windows PC with what build-reproducible.ps1 needs (rustup, and Visual
# Studio or its Build Tools with MSVC 14.44.35207), plus git, Node.js and
# Python 3. Run it from a clone of this repository; a commit the clone doesn't
# have is fetched.
param([string]$Version)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$catalog = 'https://thehubs.gg/downloads/windows-native/catalog.json'
$statements = 'https://raw.githubusercontent.com/AscentsGG/hubs-releases/main/apps/windows'
$python = if (Get-Command python -ErrorAction SilentlyContinue) { 'python' } else { 'python3' }
$work = Join-Path ([IO.Path]::GetTempPath()) ("hubs-check-" + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory $work | Out-Null

try {
    if (-not $Version) { $Version = (Invoke-RestMethod $catalog).releases[0].version }
    "Hubs for Windows $Version"

    $json = Join-Path $work 'statement.json'
    $sig = Join-Path $work 'statement.json.sig'
    try {
        Invoke-WebRequest "$statements/$Version.json" -OutFile $json
        Invoke-WebRequest "$statements/$Version.json.sig" -OutFile $sig
    } catch {
        throw "No signed statement for $Version in hubs-releases."
    }
    node (Join-Path $root 'tools/verify-statement.mjs') $json $sig (Join-Path $root 'tools/release-signing-key.pem') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "The statement for $Version is NOT signed by the Hubs release key." }
    "Statement signed by the Hubs release key."
    $statement = Get-Content -Raw $json | ConvertFrom-Json
    if ($statement.version -ne $Version -or $statement.app -ne 'windows') { throw "The statement is for another release." }

    $commit = $statement.library.commit
    "Library built from hubs-encryption $commit"
    $source = Join-Path $work 'source'
    git clone -q --no-checkout $root $source
    git -C $source cat-file -e "$commit^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { git -C $source fetch -q https://github.com/AscentsGG/hubs-encryption.git $commit }
    git -C $source checkout -q $commit
    if ($LASTEXITCODE -ne 0) { throw "Couldn't check out $commit." }

    $log = Join-Path $work 'build.log'
    pwsh -NoProfile -File (Join-Path $source 'rust/hubs-mls-ffi/build-reproducible.ps1') *> $log
    if ($LASTEXITCODE -ne 0) { Get-Content $log | Write-Host; throw "The rebuild failed." }
    Get-Content $log | Select-Object -Last 4
    $dll = Join-Path $source 'rust/target/x86_64-pc-windows-msvc/release/hubs_mls_ffi.dll'

    $url = $statement.download.url
    $zip = Join-Path $work 'release.zip'
    Invoke-WebRequest $url -OutFile $zip
    $found = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    if ($found -ne $statement.download.sha256) { throw "The download's SHA-256 ($found) is not the statement's." }
    "Downloaded $url, SHA-256 as the statement says."

    $compared = & $python (Join-Path $source 'rust/hubs-mls-ffi/compare-dll.py') $dll $zip
    $code = $LASTEXITCODE
    $compared
    if ($code -ne 0) { throw "The release's library is not the one this commit builds." }
    $digest = $statement.library.authenticodeDigest
    if (-not ($compared -contains "Published: $digest")) { throw "The release's Authenticode digest is not the statement's $digest." }
    "The release's library is the one this repository builds at $commit, and its Authenticode digest is the statement's."
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
