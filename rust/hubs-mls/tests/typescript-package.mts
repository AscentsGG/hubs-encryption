// Loads the TypeScript implementation for the Node scripts in this folder.
//
// The scripts sit outside the TypeScript package, so Node cannot find the
// package or its dependencies by name from here. This module finds the
// package folder, then loads its entry point and ts-mls (as the package
// installed it) by path. The folder is HUBS_TYPESCRIPT_DIR when set, and
// otherwise the current folder. Run the scripts from the package's folder
// (`typescript/` at the root of this repository) after `npm ci` there, so
// that `node --import tsx` finds tsx too.
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const packageDir = resolve(process.env.HUBS_TYPESCRIPT_DIR ?? ".");
const manifestPath = join(packageDir, "package.json");
if (!existsSync(manifestPath))
  throw new Error(
    `no TypeScript package at ${packageDir} (set HUBS_TYPESCRIPT_DIR to its folder)`,
  );
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const require = createRequire(manifestPath);
const load = (specifier: string) =>
  import(pathToFileURL(require.resolve(specifier)).href);

/** The package's entry point, found through its own name and exports. */
export const privateMessages = await load(manifest.name);

/** ts-mls, the same copy the package uses. */
export const tsMls = await load("ts-mls");
export const tsMlsRatchetTree = await load("ts-mls/ratchetTree.js");

/** The installed ts-mls version. Its package.json is not exported, so it
 * is found by walking up from the entry point. */
export const tsMlsVersion: string = (() => {
  for (let dir = dirname(require.resolve("ts-mls")); ; dir = dirname(dir)) {
    const path = join(dir, "package.json");
    if (existsSync(path)) {
      const found = JSON.parse(readFileSync(path, "utf8"));
      if (found.name === "ts-mls") return found.version;
    }
    if (dirname(dir) === dir) throw new Error("ts-mls package.json not found");
  }
})();
