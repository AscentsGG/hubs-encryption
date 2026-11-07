#!/bin/zsh
# Checks the Hubs for Mac release thehubs.gg serves now against this repository.
#
#   tools/check-mac-release.sh            the current release
#   tools/check-mac-release.sh 0.1.69     a given version
#
# 1. Reads the release from thehubs.gg's catalog, and its signed statement from
#    github.com/AscentsGG/hubs-releases (apps/mac/<version>.json).
# 2. Verifies the statement's signature with tools/release-signing-key.pem.
# 3. Builds the encryption library at the commit the statement names, with
#    that commit's rust/hubs-mls/build-reproducible.sh.
# 4. Downloads the release, checks its SHA-256 against the statement, and
#    compares the library inside it with the rebuild (compare-macho.py), then
#    checks the code digests are the ones the statement names.
#
# Needs a Mac with what build-reproducible.sh needs (rustup, and Command Line
# Tools 26.4 or Xcode 26.4.1), plus git, curl, python3 and openssl. Run it from
# a clone of this repository; a commit the clone doesn't have is fetched.
set -euo pipefail

root=${0:A:h:h}
catalog=https://thehubs.gg/downloads/mac-native/catalog.json
statements=https://raw.githubusercontent.com/AscentsGG/hubs-releases/main/apps/mac
work=$(mktemp -d)
trap 'rm -rf $work' EXIT
field() { python3 -c '
import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2:]:
    value = value[key]
print(value)' $work/statement.json "$@"; }

version=${1:-$(curl -fsS $catalog | python3 -c 'import json,sys; print(json.load(sys.stdin)["releases"][0]["version"])')}
print "Hubs for Mac $version"

curl -fsS -o $work/statement.json $statements/$version.json \
  || { print -u2 "No signed statement for $version in hubs-releases."; exit 1; }
curl -fsS -o $work/statement.json.sig $statements/$version.json.sig
base64 -d -i $work/statement.json.sig > $work/signature
openssl pkeyutl -verify -pubin -inkey $root/tools/release-signing-key.pem -rawin \
  -in $work/statement.json -sigfile $work/signature >/dev/null \
  || { print -u2 "The statement for $version is NOT signed by the Hubs release key."; exit 1; }
print "Statement signed by the Hubs release key."
[[ $(field version) == $version && $(field app) == mac ]] || { print -u2 "The statement is for another release."; exit 1; }

commit=$(field library commit)
print "Library built from hubs-encryption $commit"
git clone -q --no-checkout $root $work/source
git -C $work/source cat-file -e "$commit^{commit}" 2>/dev/null \
  || git -C $work/source fetch -q https://github.com/AscentsGG/hubs-encryption.git $commit
git -C $work/source checkout -q $commit
zsh $work/source/rust/hubs-mls/build-reproducible.sh $work/rebuild 2>$work/build.log | tail -1 \
  || { cat $work/build.log >&2; print -u2 "The rebuild failed."; exit 1; }

url=$(field download url)
curl -fsS -o $work/release.zip $url
found=$(shasum -a 256 $work/release.zip | cut -d' ' -f1)
[[ $found == $(field download sha256) ]] || { print -u2 "The download's SHA-256 ($found) is not the statement's."; exit 1; }
print "Downloaded $url, SHA-256 as the statement says."

python3 $work/source/rust/hubs-mls/compare-macho.py $work/rebuild/HubsMLSFFI.framework $work/release.zip | tee $work/compare.txt
for arch in arm64 x86_64; do
  digest=$(field library codeDigests $arch)
  grep -q "  $arch: $digest " $work/compare.txt || { print -u2 "The $arch code digest is not the statement's $digest."; exit 1; }
done
print "The release's library is the one this repository builds at $commit, and its digests are the statement's."
