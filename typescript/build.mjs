#!/usr/bin/env node
// Builds the two files a browser runs for private conversations and calls:
//
//   dist/hubs-private-messages.js  everything in src/index.ts
//   dist/hubs-private-calls.js     the call encryption only (src/calls.ts)
//
// Each is one self-contained ES module. The build is repeatable: the same
// source, lockfile and bundler version give the same bytes on any computer,
// so anyone can rebuild them and compare their SHA-256 with the files a site
// serves (docs/release-fingerprints.md).
//
//   node build.mjs           build and print each file's SHA-256
//   node build.mjs --check   build, and fail if dist/ differs

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const HERE = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

export const ENTRIES = {
  "hubs-private-messages": "src/index.ts",
  "hubs-private-calls": "src/calls.ts",
};

/** The bundler version the build is pinned to (package.json devDependencies). */
export const BUNDLER_VERSION = JSON.parse(
  readFileSync(join(HERE, "package.json"), "utf8"),
).devDependencies.rolldown;

/*
 * ts-mls loads the libraries for its other ciphersuites on demand. Only
 * ciphersuite 1 is used, so those imports resolve to a module that refuses.
 */
const UNUSED_SUITES =
  /^(@hpke\/(chacha20poly1305|dhkem-x448|hybridkem-x-wing|ml-kem)|@noble\/curves\/(ed25519|ed448|nist)\.js|@noble\/post-quantum\/.+)$/;
const UNUSED_ID = "\0unused-ciphersuite";
const unusedSuites = {
  name: "unused-ciphersuites",
  resolveId(id, importer) {
    return /[\\/]node_modules[^\\/]*[\\/]ts-mls[\\/]/.test(importer ?? "") &&
      UNUSED_SUITES.test(id)
      ? UNUSED_ID
      : null;
  },
  load(id) {
    return id === UNUSED_ID
      ? 'throw new Error("This ciphersuite is not used by Hubs private conversations.");'
      : null;
  },
};

export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

/** One standalone file's bytes. */
export async function buildFile(name) {
  const { rolldown, VERSION } = await import(
    require.resolve("rolldown", { paths: [HERE] })
  );
  if (VERSION !== BUNDLER_VERSION)
    throw new Error(
      `This build is pinned to rolldown ${BUNDLER_VERSION}, but ${VERSION} is installed.`,
    );
  const bundle = await rolldown({
    input: join(HERE, ENTRIES[name]),
    cwd: HERE,
    platform: "browser",
    plugins: [unusedSuites],
    logLevel: "silent",
  });
  try {
    const { output } = await bundle.generate({
      format: "esm",
      minify: true,
      comments: { legal: false },
      codeSplitting: false,
      sourcemap: false,
    });
    if (output.length !== 1)
      throw new Error(`${name} did not build to one file.`);
    return Buffer.from(output[0].code, "utf8");
  } finally {
    await bundle.close();
  }
}

/** Every standalone file, by name. */
export async function buildAll() {
  const files = {};
  for (const name of Object.keys(ENTRIES)) files[name] = await buildFile(name);
  return files;
}

async function main() {
  const check = process.argv.includes("--check");
  const files = await buildAll();
  const dist = join(HERE, "dist");
  let differs = false;
  for (const [name, bytes] of Object.entries(files)) {
    const path = join(dist, `${name}.js`);
    if (check) {
      const same =
        existsSync(path) && sha256(readFileSync(path)) === sha256(bytes);
      if (!same) differs = true;
      console.log(
        `${same ? "same" : "DIFFERENT"}  ${sha256(bytes)}  ${name}.js`,
      );
    } else {
      mkdirSync(dist, { recursive: true });
      writeFileSync(path, bytes);
      console.log(`${sha256(bytes)}  ${name}.js`);
    }
  }
  if (differs) process.exit(1);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
