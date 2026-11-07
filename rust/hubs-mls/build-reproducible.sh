#!/bin/zsh
# Builds HubsMLSFFI.framework, the encryption library in Hubs for Mac, so it
# comes out the same, byte for byte, on any Mac and in any folder. The Hubs for
# Mac release build runs this very script from a checkout of this repository at
# the commit its release notes name, and so can anyone checking that release.
#
# Needs rustup, and Apple's Command Line Tools 26.4 or Xcode 26.4.1, which have
# the same linker and give the same library. REPRODUCIBLE.md, beside this script, says how to
# compare the result with a release and what each pin below is for. Everything
# pinned here ends up in the library, so changing any of it changes the library.
#
#   rust/hubs-mls/build-reproducible.sh [output folder]
#   rust/hubs-mls/build-reproducible.sh --twice    # two builds in two folders, compared
set -euo pipefail

crate=${0:A:h}
workspace=${crate:h}
root=${workspace:h}
rust=$(sed -n 's/^channel = "\(.*\)"/\1/p' $workspace/rust-toolchain.toml)
targets=(aarch64-apple-darwin x86_64-apple-darwin)
name=HubsMLSFFI
min_macos=15.0
# The linker and the SDK go into the library. The macOS 26.4 SDK in Command Line
# Tools 26.4 (25E236) and the one in Xcode 26.4.1 (25E251, on GitHub's macOS
# runners) are different builds that give the same library.
linker=ld-1266.8
sdk_builds=(25E236 25E251)

if [[ ${1:-} == --twice ]]; then
  # The proof: the whole repository copied to two folders of different names
  # and depths, built in each, and compared.
  work=$(mktemp -d)
  trap 'rm -rf $work' EXIT
  for folder in $work/a/hubs-encryption $work/second/copy/of/it; do
    mkdir -p $folder
    rsync -a --exclude .git --exclude rust/target --exclude out $root/ $folder/
    zsh $folder/rust/hubs-mls/build-reproducible.sh $folder/out >/dev/null
  done
  # Every file's SHA-256 and every link's target, in the order of their names.
  listing() { (cd $1 && find . \( -type f -o -type l \) | LC_ALL=C sort | while read -r entry; do
    if [[ -L $entry ]]; then print "$entry -> $(readlink $entry)"; else print "$entry $(shasum -a 256 $entry | cut -d' ' -f1)"; fi
  done) }
  one=$work/a/hubs-encryption/out
  two=$work/second/copy/of/it/out
  print "first:  $(shasum -a 256 $one/$name.framework/Versions/A/$name | cut -d' ' -f1)"
  print "second: $(shasum -a 256 $two/$name.framework/Versions/A/$name | cut -d' ' -f1)"
  if [[ "$(listing $one)" == "$(listing $two)" ]]; then
    print "The two builds are identical."
  else
    print -u2 "The two builds differ."
    exit 1
  fi
  exit 0
fi

out=${1:-$workspace/target/mac}
out=${out:A}

# The linker and SDK: Xcode 26.4.1 where it is installed under that name (as on
# GitHub's macOS runners), else the Command Line Tools.
if [[ -z ${DEVELOPER_DIR:-} ]]; then
  if [[ -d /Applications/Xcode_26.4.1.app ]]; then
    export DEVELOPER_DIR=/Applications/Xcode_26.4.1.app/Contents/Developer
  else
    export DEVELOPER_DIR=/Library/Developer/CommandLineTools
  fi
fi
found_linker=$(xcrun ld -v 2>&1 | sed -n 's/.*PROJECT:\(ld-[0-9.]*\).*/\1/p' | head -1)
found_sdk=$(xcrun --sdk macosx --show-sdk-build-version)
if [[ $found_linker != $linker || ${sdk_builds[(Ie)$found_sdk]} -eq 0 ]]; then
  print -u2 "This needs $linker and the macOS SDK ${(j: or :)sdk_builds} (Command Line Tools 26.4 or Xcode 26.4.1)."
  print -u2 "$DEVELOPER_DIR has $found_linker and SDK $found_sdk. Set DEVELOPER_DIR to one that matches."
  exit 1
fi
export SDKROOT=$(xcrun --sdk macosx --show-sdk-path)
export MACOSX_DEPLOYMENT_TARGET=$min_macos
# Archive members carry no dates.
export ZERO_AR_DATE=1

# The two paths that would otherwise end up in panic messages: this checkout,
# and cargo's folder of downloaded crates. The install name tells the app where
# the library sits inside it, and -S leaves out the debug map (the paths of the
# object files).
cargo_home=${CARGO_HOME:-$HOME/.cargo}
flags=(--remap-path-prefix=$root=. --remap-path-prefix=$cargo_home=cargo
       -C link-arg=-Wl,-install_name,@rpath/$name.framework/Versions/A/$name
       -C link-arg=-Wl,-S -C link-arg=-Wl,-adhoc_codesign)
export CARGO_ENCODED_RUSTFLAGS=${(pj:\x1f:)flags}
unset RUSTFLAGS
export CARGO_INCREMENTAL=0

cd $workspace
rustup toolchain install $rust --profile minimal ${targets/#/--target=} >/dev/null
for target in $targets; do
  # The core as a dynamic library (Cargo.toml lists staticlib for the iPhone).
  cargo +$rust rustc --package hubs-mls --lib --crate-type cdylib --release --locked \
    --target $target --target-dir target
done
cargo +$rust build --package uniffi-bindgen --locked --target-dir target

rm -rf $out
mkdir -p $out
framework=$out/$name.framework
version=$framework/Versions/A
mkdir -p $version/Headers $version/Modules $version/Resources
xcrun lipo -create target/aarch64-apple-darwin/release/libhubs_mls.dylib \
  target/x86_64-apple-darwin/release/libhubs_mls.dylib -output $version/$name

# UniFFI's Swift and C header, generated from the library itself.
target/debug/uniffi-bindgen generate --library target/aarch64-apple-darwin/release/libhubs_mls.dylib \
  --language swift --out-dir $out/swift >/dev/null
cp $out/swift/$name.h $version/Headers/
cat > $version/Modules/module.modulemap <<MAP
framework module $name {
    header "$name.h"
    export *
}
MAP
core_version=$(sed -n 's/^version = "\(.*\)"/\1/p' $crate/Cargo.toml | head -1)
cat > $version/Resources/Info.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>$name</string>
	<key>CFBundleIdentifier</key>
	<string>gg.thehubs.$name</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>$name</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>$core_version</string>
	<key>CFBundleVersion</key>
	<string>$core_version</string>
	<key>LSMinimumSystemVersion</key>
	<string>$min_macos</string>
</dict>
</plist>
PLIST
ln -s A $framework/Versions/Current
for part in $name Headers Modules Resources; do ln -s Versions/Current/$part $framework/$part; done

print "Rust $rust, $found_linker, macOS SDK $found_sdk ($DEVELOPER_DIR)"
print "Built from $root"
print "$name: $version/$name"
print "sha256 $(shasum -a 256 $version/$name | cut -d' ' -f1) (unsigned; compare a release with compare-macho.py)"
