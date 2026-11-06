#!/usr/bin/env node
// Release fingerprints: a signed list of every file a Hubs web release serves,
// and a check anyone can run against the live site. Node 20 or newer, no
// dependencies. See docs/release-fingerprints.md.
//
//   node tools/check-release.mjs [check] [--release R | --current] [--site URL]
//        [--from DIR_OR_URL] [--key PEM] [--all | --sample N] [--rebuilt DIST]
//   node tools/check-release.mjs make <release folder> [--site URL] [--out FILE]
//   node tools/check-release.mjs sign <statement.json> --key <private PEM>
//   node tools/check-release.mjs keygen <private PEM out> <public PEM out>
//
// `check` is the default command and the public part. We run `make` and
// `sign` on the computer that holds the release signing key, never on a
// server.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const FORMAT = "hubs-release-fingerprints/1";
export const DEFAULT_SITE = "https://thehubs.gg";
export const DEFAULT_FROM =
  "https://raw.githubusercontent.com/AscentsGG/hubs-releases/main/releases";
const HERE = dirname(fileURLToPath(import.meta.url));
/**
 * The Hubs release signing key (Ed25519, public). A copy beside this script or
 * passed with --key wins, so a rotated key can be used before this file changes.
 */
export const RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqw24MtztP9Gp2UKAhgVIjx4Y+Y0kM8IxpabNhN3K3ks=
-----END PUBLIC KEY-----
`;
const KEY_FILES = [join(HERE, "release-signing-key.pem")];

/** Headers that decide what a page may load and run. The check compares them exactly. */
export const PAGE_HEADERS = [
  "content-security-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "strict-transport-security",
  "x-content-type-options",
];

/** Pages whose HTML must be one of the release's built pages once the asset origin is taken out. */
export const PAGES = ["/app", "/login"];

/** Public pages the server draws for each visit: every script and stylesheet they load must be on the list. */
export const PUBLIC_PAGES = ["/", "/download"];

/** Served files the check fetches: built code and styles, and the unhashed files that decide what loads. */
export const CHECKED =
  /^\/(?:assets|vendor)\/|^\/(?:service-worker\.js|prerendered\.js|offline\.js|offline\.css|offline\.html|manifest\.webmanifest)$/;

export const NOT_COVERED = [
  "Scripts from other companies that run on their own origins, such as the YouTube and Twitch players. Hubs shows them in frames and does not control them.",
  "What a browser actually runs from its own cache. A list says what the site sends, not what an earlier visit stored.",
  "The desktop and phone apps. Their code is covered by the signatures on their installers and store builds.",
  "Hosted hub apps under /app-bundles/ and the glasses site, which run on separate origins with no access to private conversations.",
  "One person being sent different files. A check from your own connection only proves what you were sent.",
];

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/**
 * The page as built: every built-file address in a src or href attribute,
 * and every key of the import map that pins those files, back on the page's
 * own origin.
 */
export function pageAsBuilt(html) {
  return html
    .replace(/(\s(?:src|href)=")(?:https?:\/\/[^"/\s]+)?(\/assets\/)/g, "$1$2")
    .replace(
      /(<script\s+type="importmap">)([\s\S]*?)(<\/script>)/,
      (_all, open, body, close) =>
        `${open}${body.replace(/"(?:https?:\/\/[^"/\s]+)?(\/assets\/)/g, '"$1')}${close}`,
    );
}

/** The asset origin a served page names for its entry script, or null when it loads from itself. */
export function assetOriginOf(html) {
  const match = html.match(/\ssrc="(https:\/\/[^"/\s]+)\/assets\/[^"]+\.js"/);
  return match ? match[1] : null;
}

/** The built page as the Hubs server sends it with `origin` (null: none): the
 * same moves as shellWithAssetOrigin in server/static-assets.ts. */
export function withAssetOrigin(html, origin) {
  const to = origin ?? "";
  return html
    .replace(
      /(\s(?:src|href)=")(?:https?:\/\/[^"/\s]+)?(\/assets\/)/g,
      (_all, attribute, assets) => `${attribute}${to}${assets}`,
    )
    .replace(
      /(<script\s+type="importmap">)([\s\S]*?)(<\/script>)/,
      (_all, open, body, close) =>
        `${open}${body.replace(/"(?:https?:\/\/[^"/\s]+)?(\/assets\/)/g, (_key, assets) => `"${to}${assets}`)}${close}`,
    );
}

/**
 * The built form of a served page, or null when the page is not a built page
 * with one asset origin applied to every address and every import map key.
 * pageAsBuilt alone maps many pages to one: a page whose scripts load from
 * the asset origin while its map pins the page's own addresses reduces to the
 * built page, yet pins nothing that loads (audit 6, AP-2).
 */
export function builtFormOf(html, origin = assetOriginOf(html)) {
  const plain = pageAsBuilt(html);
  return withAssetOrigin(plain, origin) === html ? plain : null;
}

/** The standalone encryption files a statement lists, made here or carried. */
export function encryptionFiles(statement) {
  const named = /^\/assets\/hubs-private-(?:messages|calls)-[0-9a-f]{16}\.js$/;
  return [
    ...Object.entries(statement.files),
    ...Object.entries(statement.carried).map(([path, [hash]]) => [path, hash]),
  ]
    .filter(([path]) => named.test(path))
    .sort(([a], [b]) => a.localeCompare(b));
}

/**
 * The encryption files this release's pages load, one per name: the one it
 * made, or, when it didn't rebuild that file because it hadn't changed, the
 * newest one it carries (the carried entry names the release that made it,
 * and release ids sort by time). Older carried versions stay listed only for
 * pages a browser cached.
 */
export function currentEncryptionFiles(statement) {
  const current = [];
  for (const name of ["hubs-private-calls", "hubs-private-messages"]) {
    const prefix = `/assets/${name}-`;
    const made = Object.entries(statement.files).filter(([path]) =>
      path.startsWith(prefix),
    );
    if (made.length) {
      current.push(...made);
      continue;
    }
    const carried = Object.entries(statement.carried)
      .filter(([path]) => path.startsWith(prefix))
      .sort(([, [, a]], [, [, b]]) => String(b).localeCompare(String(a)));
    if (carried.length) current.push([carried[0][0], carried[0][1][0]]);
  }
  return current;
}

/**
 * Compares the package's own build (its dist folder: hubs-private-messages.js
 * and hubs-private-calls.js) with the encryption files a release lists.
 * Returns what differs; empty when every file matches byte for byte.
 */
export function compareRebuild(encryption, dist) {
  const differences = [];
  if (!encryption.length)
    return ["This release lists no standalone encryption files."];
  for (const name of ["hubs-private-messages", "hubs-private-calls"]) {
    const listed = encryption.filter(([path]) =>
      path.startsWith(`/assets/${name}-`),
    );
    const file = join(dist, `${name}.js`);
    if (!existsSync(file)) {
      differences.push(`${file} is missing. Run npm run build first.`);
      continue;
    }
    const built = sha256(readFileSync(file));
    if (listed.length !== 1)
      differences.push(`The release lists ${listed.length} ${name} files.`);
    else if (listed[0][1] !== built)
      differences.push(
        `${name}.js: your build ${built}, the release ${listed[0][1]}`,
      );
  }
  return differences;
}

/** Stable JSON: sorted keys, one key per line, so two statements diff cleanly. */
export function stableJson(value) {
  const sorted = (item) =>
    Array.isArray(item)
      ? item.map(sorted)
      : item && typeof item === "object"
        ? Object.fromEntries(
            Object.keys(item)
              .sort()
              .map((key) => [key, sorted(item[key])]),
          )
        : item;
  return `${JSON.stringify(sorted(value), null, 1)}\n`;
}

/**
 * The statement for one release, from the operator's local build record
 * (built.json, made inside the image) and what the live site serves now.
 */
export function statementFrom(built, served, signedAt) {
  const files = {};
  for (const [path, hash] of Object.entries(built.distFiles ?? {}))
    files[path] = hash;
  const carried = {};
  const builtBy = built.retainedTrust?.builtBy ?? {};
  for (const [name, hash] of Object.entries(built.retainedAssets ?? {})) {
    carried[`/assets/${name}`] = [hash, builtBy[name] ?? null];
  }
  if (!Object.keys(files).length)
    throw new Error("The build record lists no files (distFiles).");
  if (Object.values(carried).some(([, release]) => !release))
    throw new Error("A carried file has no earlier build named for it.");
  return {
    format: FORMAT,
    release: built.release,
    commit: built.sourceCommit ?? null,
    imageId: built.imageId ?? null,
    nodeImage: built.nodeImage ?? null,
    signedAt,
    site: served.site,
    assetOrigin: served.assetOrigin,
    pageRule:
      "A page is one of the built .html files with each built-file address in a src or href attribute, and each key of its import map, moved to the asset origin.",
    headers: served.headers,
    files,
    carried,
    notCovered: NOT_COVERED,
  };
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const item = argv[i];
    if (!item.startsWith("--")) args._.push(item);
    else if (["--all", "--current", "--quiet"].includes(item))
      args[item.slice(2)] = true;
    else args[item.slice(2)] = argv[(i += 1)];
  }
  return args;
}

async function fetchBytes(url, attempt = 0) {
  try {
    const response = await fetch(url, {
      redirect: "follow",
      headers: { "user-agent": "hubs-release-fingerprints/1" },
    });
    if (response.status === 429 || response.status >= 500)
      throw new Error(`HTTP ${response.status}`);
    return {
      status: response.status,
      headers: response.headers,
      bytes: Buffer.from(await response.arrayBuffer()),
    };
  } catch (error) {
    if (attempt >= 3) throw new Error(`${url}: ${error.message}`);
    await new Promise((done) => setTimeout(done, 1000 * 2 ** attempt));
    return fetchBytes(url, attempt + 1);
  }
}

/** Fetch every (url, expected hash), 4 at a time with starts at least `gap` ms apart. */
async function checkFiles(items, gap = 350) {
  const problems = [];
  let next = 0;
  let last = 0;
  async function worker() {
    while (next < items.length) {
      const [url, expected] = items[(next += 1) - 1];
      const wait = Math.max(0, last + gap - Date.now());
      last = Date.now() + wait;
      if (wait) await new Promise((done) => setTimeout(done, wait));
      try {
        const { status, bytes } = await fetchBytes(url);
        if (status !== 200) problems.push(`${url}: HTTP ${status}`);
        else if (sha256(bytes) !== expected)
          problems.push(`${url}: different bytes (${sha256(bytes)})`);
      } catch (error) {
        problems.push(error.message);
      }
    }
  }
  await Promise.all([worker(), worker(), worker(), worker()]);
  return problems;
}

/** Every built file a page's HTML loads by address (scripts, preloads, stylesheets, icons). */
export function loadsOf(html) {
  return [
    ...pageAsBuilt(html).matchAll(
      /\s(?:src|href)="(\/(?:assets|vendor)\/[^"?#]+)"/g,
    ),
  ].map((match) => match[1]);
}

/** What the site serves now: the page headers, the asset origin, each page's built form and what public pages load. */
export async function readSite(site) {
  const headers = {};
  const pages = {};
  const publicLoads = {};
  const mixed = [];
  let assetOrigin = null;
  for (const path of [...PAGES, ...PUBLIC_PAGES]) {
    const { status, headers: got, bytes } = await fetchBytes(site + path);
    if (status !== 200) throw new Error(`${site}${path}: HTTP ${status}`);
    const html = bytes.toString("utf8");
    if (path === "/app") {
      for (const name of PAGE_HEADERS) headers[name] = got.get(name);
      assetOrigin = assetOriginOf(html);
    }
    // Every page must name the one asset origin the app shell names, on every
    // built-file address and every import map key.
    const form = builtFormOf(html, assetOrigin);
    if (form === null) mixed.push(path);
    if (PAGES.includes(path)) pages[path] = sha256(form ?? html);
    else publicLoads[path] = loadsOf(html);
  }
  return { site, headers, assetOrigin, pages, publicLoads, mixed };
}

/** Compare a statement with the live site. Returns a list of problems; empty means it matches. */
export async function compare(
  statement,
  served,
  { sample = null, all = false, log = () => {}, gap = 350 } = {},
) {
  const problems = [];
  for (const name of PAGE_HEADERS) {
    if ((served.headers[name] ?? null) !== (statement.headers[name] ?? null))
      problems.push(`The ${name} header differs from the signed one.`);
  }
  const built = new Set(
    Object.entries(statement.files)
      .filter(([path]) => path.endsWith(".html"))
      .map(([, hash]) => hash),
  );
  for (const [path, hash] of Object.entries(served.pages)) {
    if (!built.has(hash))
      problems.push(
        `The page at ${path} is not one of the release's built pages.`,
      );
  }
  for (const path of served.mixed ?? [])
    problems.push(
      `The page at ${path} does not name one asset origin on every built file and import map key.`,
    );
  const listed = new Set([
    ...Object.keys(statement.files),
    ...Object.keys(statement.carried),
  ]);
  for (const [path, loads] of Object.entries(served.publicLoads ?? {}))
    for (const file of loads)
      if (!listed.has(file))
        problems.push(
          `The page at ${path} loads ${file}, which is not on the list.`,
        );
  if ((served.assetOrigin ?? null) !== (statement.assetOrigin ?? null))
    problems.push(
      `The page loads its code from ${served.assetOrigin ?? "itself"}, the statement says ${statement.assetOrigin ?? "itself"}.`,
    );
  // Every file this release made is fetched. Carried files were checked when the
  // release that made them was signed, so a sample of them is enough unless --all.
  const made = Object.entries(statement.files).filter(([path]) =>
    CHECKED.test(path),
  );
  const carried = Object.entries(statement.carried).map(([path, [hash]]) => [
    path,
    hash,
  ]);
  const chosen = [
    ...made,
    ...(all ? carried : pick(carried, sample ?? 100, statement.release)),
  ];
  const items = chosen.map(([path, hash]) => [statement.site + path, hash]);
  if (statement.assetOrigin)
    for (const [path, hash] of chosen)
      if (/^\/(assets|vendor)\//.test(path))
        items.push([statement.assetOrigin + path, hash]);
  log(`Checking ${items.length} files.`);
  problems.push(...(await checkFiles(items, gap)));
  return problems;
}

/** A sample of carried files, chosen by the release name so a rerun checks the same ones. */
function pick(list, count, seed) {
  const ranked = [...list].sort(([a], [b]) =>
    sha256(seed + a).localeCompare(sha256(seed + b)),
  );
  return ranked.slice(0, Math.max(0, count));
}

function publicKey(path) {
  if (path) return createPublicKey(readFileSync(path));
  for (const file of KEY_FILES)
    if (existsSync(file)) return createPublicKey(readFileSync(file));
  return createPublicKey(RELEASE_PUBLIC_KEY);
}

async function readStatement(from, release) {
  const name = `${release}.json`;
  if (/^https:\/\//.test(from)) {
    const body = await fetchBytes(`${from}/${name}`);
    const signature = await fetchBytes(`${from}/${name}.sig`);
    if (body.status !== 200 || signature.status !== 200)
      throw new Error(`No signed statement for ${release} at ${from}.`);
    return {
      bytes: body.bytes,
      signature: signature.bytes.toString("utf8").trim(),
    };
  }
  return {
    bytes: readFileSync(join(from, name)),
    signature: readFileSync(join(from, `${name}.sig`), "utf8").trim(),
  };
}

async function main(argv) {
  const args = parseArgs(argv);
  // With no command, or only options, the command is `check`.
  const [command = "check", target] = args._;
  if (command === "keygen") {
    const [, privateOut, publicOut] = args._;
    if (!privateOut || !publicOut || existsSync(privateOut))
      throw new Error("keygen <new private PEM> <public PEM>");
    const { privateKey, publicKey: key } = generateKeyPairSync("ed25519");
    writeFileSync(
      privateOut,
      privateKey.export({ type: "pkcs8", format: "pem" }),
      { mode: 0o600, flag: "wx" },
    );
    writeFileSync(publicOut, key.export({ type: "spki", format: "pem" }));
    console.log(`Public key written to ${publicOut}.`);
    return 0;
  }
  if (command === "make") {
    if (!target) throw new Error("make <release folder>");
    const built = JSON.parse(readFileSync(join(target, "built.json"), "utf8"));
    const site = args.site ?? DEFAULT_SITE;
    const served = await readSite(site);
    const live = JSON.parse(
      (await fetchBytes(`${site}/api/client-release`)).bytes.toString("utf8"),
    ).release;
    if (live !== built.release)
      throw new Error(`${site} runs ${live}, not ${built.release}.`);
    const statement = statementFrom(
      built,
      served,
      new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    );
    const problems = await compare(statement, served, {
      sample: 100,
      log: console.log,
    });
    if (problems.length) {
      console.error(problems.slice(0, 40).join("\n"));
      throw new Error(`${problems.length} problems: nothing signed.`);
    }
    const out = args.out ?? join(target, `${built.release}.json`);
    writeFileSync(out, stableJson(statement), { flag: "wx" });
    console.log(
      `Statement written to ${out}: ${Object.keys(statement.files).length} files made by this release, ${Object.keys(statement.carried).length} carried.`,
    );
    return 0;
  }
  if (command === "sign") {
    if (!target || !args.key)
      throw new Error("sign <statement.json> --key <private PEM>");
    const bytes = readFileSync(target);
    const statement = JSON.parse(bytes.toString("utf8"));
    if (statement.format !== FORMAT)
      throw new Error("Not a release statement.");
    const signature = sign(
      null,
      bytes,
      createPrivateKey(readFileSync(args.key)),
    ).toString("base64");
    writeFileSync(`${target}.sig`, `${signature}\n`, { flag: "wx" });
    console.log(`Signed ${statement.release}.`);
    return 0;
  }
  if (command === "check") {
    const site = args.site ?? DEFAULT_SITE;
    let release = args.release;
    if (!release || args.current)
      release = JSON.parse(
        (await fetchBytes(`${site}/api/client-release`)).bytes.toString("utf8"),
      ).release;
    const { bytes, signature } = await readStatement(
      args.from ?? DEFAULT_FROM,
      release,
    );
    if (
      !verify(
        null,
        bytes,
        publicKey(args.key),
        Buffer.from(signature, "base64"),
      )
    )
      throw new Error(
        `The statement for ${release} is not signed by the Hubs release key.`,
      );
    const statement = JSON.parse(bytes.toString("utf8"));
    if (statement.format !== FORMAT || statement.release !== release)
      throw new Error("The statement names another release.");
    console.log(
      `Signed statement for ${release} (commit ${statement.commit ?? "not recorded"}, signed ${statement.signedAt}).`,
    );
    const served = await readSite(site);
    const problems = await compare({ ...statement, site }, served, {
      sample: Number(args.sample ?? 120),
      all: Boolean(args.all),
      log: console.log,
    });
    if (problems.length) {
      console.log(`${site} does NOT match the signed statement:`);
      for (const line of problems.slice(0, 60)) console.log(`  ${line}`);
      return 1;
    }
    console.log(`${site} matches the signed statement for ${release}.`);
    // The encryption files, as the open source package builds them: rebuild
    // the package (npm run build) and compare these with what it prints.
    const encryption = encryptionFiles(statement);
    if (encryption.length) {
      console.log(
        "Encryption files in this release (rebuild the package to compare):",
      );
      for (const [path, hash] of encryption) console.log(`  ${hash}  ${path}`);
    }
    // --rebuilt <dist>: compare a rebuild of the package with the release.
    if (args.rebuilt) {
      // A rebuild is compared with the files this release's pages load, not
      // older versions kept for cached pages.
      const differences = compareRebuild(
        currentEncryptionFiles(statement),
        args.rebuilt,
      );
      if (differences.length) {
        console.log("Your rebuild does NOT match this release:");
        for (const line of differences) console.log(`  ${line}`);
        return 1;
      }
      console.log(
        "Your rebuild matches this release: thehubs.gg runs the encryption files the package builds.",
      );
    }
    console.log("Not covered by this check:");
    for (const line of statement.notCovered) console.log(`  ${line}`);
    return 0;
  }
  console.log(
    "Usage: check [--current | --release R] [--site URL] [--all | --sample N] [--rebuilt DIST] | make <folder> | sign <file> --key <pem> | keygen <private> <public>",
  );
  return 2;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      console.error(error.message);
      process.exit(1);
    },
  );
}
