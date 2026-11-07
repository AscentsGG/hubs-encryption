# Builds hubs_mls_ffi.dll, the encryption library in Hubs for Windows, so it comes
# out the same, byte for byte, on any PC and in any folder. The Hubs for Windows
# release build runs this very script from a checkout of this repository at the
# commit its release notes name, and so can anyone checking that release.
#
# Needs rustup, and Visual Studio or its Build Tools with MSVC 14.44.35207
# (component Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64).
# REPRODUCIBLE.md, beside this script, says how to compare the result with a
# release and what each pin below is for. Everything pinned here ends up in the
# DLL, so changing any of it changes the DLL.
$ErrorActionPreference = 'Stop'

$msvc = '14.44.35207'
$sdk = '10.0.26100.9457'
$sdkSha256 = '52bd17c63d3b6d268f385c358f34d0eb595b9c1deb3273855abd2ec5c095d132'
$target = 'x86_64-pc-windows-msvc'

$crate = $PSScriptRoot
$workspace = (Resolve-Path (Join-Path $crate '..')).Path
$root = (Resolve-Path (Join-Path $workspace '..')).Path
$rust = (Select-String -Path (Join-Path $workspace 'rust-toolchain.toml') -Pattern 'channel = "(.+)"').Matches[0].Groups[1].Value

# MSVC: the linker and the C runtime go into the DLL.
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw "No Visual Studio with the C++ tools here." }
cmd /c "`"$vs\VC\Auxiliary\Build\vcvars64.bat`" -vcvars_ver=$msvc && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { Set-Item "env:$($Matches[1])" $Matches[2] }
}
if ($env:VCToolsVersion -ne $msvc) { throw "MSVC $msvc isn't installed here (found '$env:VCToolsVersion'). Add it in the Visual Studio Installer." }

# The Windows SDK's libraries, from Microsoft's versioned package. The installed
# SDK's folder name doesn't pin them: two PCs can both say 10.0.26100.0 with
# different kernel32.lib files, and that changes the DLL's import hints.
$work = Join-Path ([IO.Path]::GetTempPath()) "hubs-windows-sdk-$sdk"
if (-not (Test-Path (Join-Path $work 'c\um\x64\kernel32.lib'))) {
    $package = "$work.zip"
    Invoke-WebRequest "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp.x64/$sdk/microsoft.windows.sdk.cpp.x64.$sdk.nupkg" -OutFile $package
    $found = (Get-FileHash -Algorithm SHA256 $package).Hash.ToLowerInvariant()
    if ($found -ne $sdkSha256) { throw "The Windows SDK package is not the expected one: $found." }
    Expand-Archive -Force $package $work
}
$env:LIB = "$work\c\um\x64;$work\c\ucrt\x64;$env:LIB"

# The two paths that would otherwise end up in panic messages: this checkout, and
# cargo's folder of downloaded crates. Encoded, so a folder with a space in its
# name works; this replaces RUSTFLAGS, which splits on spaces.
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME '.cargo' }
$env:CARGO_ENCODED_RUSTFLAGS = @('-C', 'link-arg=/Brepro', "--remap-path-prefix=$root=.", "--remap-path-prefix=$cargoHome=cargo") -join [char]0x1f
Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue
$env:CARGO_INCREMENTAL = '0'

Push-Location $workspace
try {
    rustup toolchain install $rust --profile minimal
    if ($LASTEXITCODE -ne 0) { throw "rustup couldn't install Rust $rust." }
    cargo "+$rust" build --package hubs-mls-ffi --release --locked --target $target --target-dir target
    if ($LASTEXITCODE -ne 0) { throw "The build failed." }
} finally {
    Pop-Location
}

$dll = Join-Path $workspace "target\$target\release\hubs_mls_ffi.dll"
"Rust $rust, MSVC $msvc (link.exe $((Get-Item (Get-Command link.exe).Source).VersionInfo.FileVersion)), Windows SDK package $sdk"
"Built from $root"
"hubs_mls_ffi.dll: $dll"
"sha256 $((Get-FileHash -Algorithm SHA256 $dll).Hash.ToLowerInvariant()) (the unsigned file; compare a release with compare-dll.py)"
# The Hubs for Windows release build ships this very file, rather than letting a
# later step build it again.
if ($env:GITHUB_ENV) { "HubsMlsPrebuilt=$dll" >> $env:GITHUB_ENV }
