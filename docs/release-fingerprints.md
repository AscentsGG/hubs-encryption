# Release fingerprints

The encryption in private conversations is only as good as the code your browser runs. Open-sourcing the encryption shows what that code should be. Release fingerprints let you check that thehubs.gg actually serves it, release by release, without trusting us.

## What we publish

With every web release we publish a signed statement in [github.com/AscentsGG/hubs-releases](https://github.com/AscentsGG/hubs-releases), under `releases/<release>.json`, with its signature beside it in `<release>.json.sig`. A statement holds:

- **The release and the commit it was built from.** `release` matches what `https://thehubs.gg/api/client-release` reports.
- **Every file the release made, with its SHA-256.** That covers scripts, stylesheets, workers, WebAssembly, the camera background runtime and model, the service worker, and the offline pages.
- **Every older file the release still carries**, with its SHA-256 and the release that made it. These stay for pages that were opened before the release and still load their own files. A carried file is kept only when its bytes match what that earlier build made. Anything else on a server is dropped before the build.
- **The headers that decide what a page may load and run**, exactly as served: the content security policy, permissions policy, cross-origin policies, HSTS and nosniff.
- **The asset origin.** Production loads built files from `https://cdn.thehubs.gg`. The page itself always comes from thehubs.gg.
- **The rule that turns a built page into the served page.** The server moves each built-file address in a `src` or `href` attribute to the asset origin, and nothing else.
- **What the statement does not cover** (below).

## Pinned in the page

The page itself always comes from thehubs.gg, and it names the hash of every file it may load. The browser refuses any file whose bytes differ, so the CDN that serves those files cannot change them. This covers:

- the entry script, its preloads and stylesheets, through `integrity` attributes;
- every other script and stylesheet the release made, including lazy screens, through an import map;
- the voice code's WebAssembly and models, fetched with their hash.

The camera background runtime and one audio worklet cannot carry a hash, so they load from thehubs.gg instead. Safety codes, the Call code and the device link check number use system fonts; other text uses web fonts from the asset origin, which are not pinned.

The import map's `integrity` key is recent. A browser that doesn't know it still checks the page's own tags and the stylesheets and preloads for lazy screens, but not lazy scripts.

## How it is made

The release runs from a computer that is not one of our servers:

1. **Build.** The release is built on our build server, and the build records the hash of every file the build made.
2. **Check.** After the release is live, that same computer fetches each page, every file the release made, and a sample of carried files. It fetches from both thehubs.gg and the asset origin, and compares them with the build's record.
3. **Sign.** Only if every one matches does it write the statement and sign it with an Ed25519 key. That key is kept only on that computer, never on a server.

The public key, also in [`tools/release-signing-key.pem`](../tools/release-signing-key.pem) and built into `tools/check-release.mjs`:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqw24MtztP9Gp2UKAhgVIjx4Y+Y0kM8IxpabNhN3K3ks=
-----END PUBLIC KEY-----
```

The raw key in base64 is `qw24MtztP9Gp2UKAhgVIjx4Y+Y0kM8IxpabNhN3K3ks=`. If we ever replace it, the new key is announced in this file and signed by the old one.

## Rebuild the encryption files yourself

The website doesn't bundle the encryption code into its own files. It runs the two files the open source package builds, unchanged:

- `hubs-private-messages-<hash>.js`, the private conversations;
- `hubs-private-calls-<hash>.js`, the call encryption.

The package's build is repeatable. The same code, lockfile and bundler version give the same bytes on any computer. To check that thehubs.gg runs exactly the published code, in a copy of this repository:

```sh
cd typescript
npm ci
npm run build
cd ..
node tools/check-release.mjs --current --rebuilt typescript/dist
```

The build prints the SHA-256 of `dist/hubs-private-messages.js` and `dist/hubs-private-calls.js`. The check verifies the signed statement, confirms thehubs.gg serves the files it lists, and compares your two files with the release's. It ends with "Your rebuild matches this release" when every byte is the same. The first 16 characters of each hash are also in the file's name on the site.

This repository's main branch holds the code the current release runs, and its own CI runs this check every day. When a release changes the encryption code, the repository gets a tag named after that release, so an older release can be checked from its tag.

## Check it yourself

You need Node 20 or newer. There are no dependencies to install.

```sh
node tools/check-release.mjs --current
```

This reads the release thehubs.gg is running and fetches its signed statement from github.com/AscentsGG/hubs-releases. It verifies the signature, then fetches the pages, the headers, every file the release made and a sample of carried files, from thehubs.gg and from the asset origin, and compares them. Useful options:

- `--all` fetches every carried file too. That's a few thousand requests, so it takes several minutes.
- `--site https://<address>` checks another address that serves Hubs, such as an organization's own domain.

You can also check a signature with OpenSSL alone:

```sh
base64 -d -i <release>.json.sig > sig.bin
openssl pkeyutl -verify -pubin -inkey tools/release-signing-key.pem -rawin -in <release>.json -sigfile sig.bin
```

A mismatch is worth reporting to security@thehubs.gg (see [SECURITY.md](../SECURITY.md)), with the output of the check.

## What it does not cover

- **What your browser actually ran.** A check fetches the files again, and a browser may run what an earlier visit stored. The page is revalidated on every load, and the service worker refuses to keep anything it did not fetch itself, but the check still proves only what was sent to the checker.
- **Being singled out.** A server that wanted to target one account could send that person different files. A check from your own connection shows only what you were sent. That is why the statement is signed and public: a different file is evidence.
- **Scripts from other companies.** The YouTube and Twitch players run in frames on their own origins, and we don't control them.
- **The desktop and phone apps.** Their code is covered by the signatures on their installers and store builds, not by these statements.
- **Hosted hub apps and the glasses site.** Hosted hub apps under `/app-bundles/` and the glasses site run on separate origins with no access to private conversations.
- **The build server itself.** A statement says what the build made and what the site serves. The encryption files can be rebuilt from the public code (above). The rest of the website's code is not public, so for those files the statement is our signed word, on the record.
