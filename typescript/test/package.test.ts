import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/*
 * The package builds on its own: its sources import only each other and the
 * dependencies its package.json pins, and use no bundler-only features.
 */
const root = fileURLToPath(new URL("..", import.meta.url));
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const sources = readdirSync(join(root, "src"))
  .filter((name) => name.endsWith(".ts"))
  .map((name) => ({
    name,
    text: readFileSync(join(root, "src", name), "utf8"),
  }));

test("sources import only each other and the pinned dependencies", () => {
  const dependencies = Object.keys(manifest.dependencies);
  for (const version of Object.values<string>(manifest.dependencies))
    assert.match(version, /^\d+\.\d+\.\d+$/, "dependencies are exact versions");
  const local = new Set(
    sources.map((s) => `./${s.name.replace(/\.ts$/, ".js")}`),
  );
  const seen = new Set<string>();
  for (const { name, text } of sources)
    for (const [, specifier] of text.matchAll(
      /(?:^|\n)\s*(?:import|export)\b[^;]*?\bfrom\s+"([^"]+)"/g,
    )) {
      seen.add(specifier);
      assert.ok(
        local.has(specifier) ||
          dependencies.some(
            (dependency) =>
              specifier === dependency ||
              specifier.startsWith(`${dependency}/`),
          ),
        `${name} imports ${specifier}`,
      );
    }
  assert.ok(
    seen.has("ts-mls") && seen.has("./protocol.js"),
    "the scan found imports",
  );
});

test("sources use no bundler-only features", () => {
  for (const { name, text } of sources) {
    assert.doesNotMatch(text, /import\.meta/, name);
    assert.doesNotMatch(text, /\bimport\s*\(/, name);
    assert.doesNotMatch(
      text,
      /from\s+"[^"]+\.(css|svg|png|json)(\?[^"]*)?"/,
      name,
    );
    assert.doesNotMatch(text, /from\s+"[^"]+\?[^"]*"/, name);
  }
});

test("index.ts re-exports every module", () => {
  const index = sources.find((s) => s.name === "index.ts")!.text;
  for (const { name } of sources)
    if (name !== "index.ts")
      assert.match(
        index,
        new RegExp(`from "\\./${name.replace(/\.ts$/, "")}\\.js"`),
        name,
      );
});
