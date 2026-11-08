// Checks a signed statement from github.com/AscentsGG/hubs-releases.
//
//   node tools/verify-statement.mjs <statement.json> <statement.json.sig> [release-signing-key.pem]
//
// The .sig file is the Ed25519 signature over the statement's exact bytes, in
// base64. The key defaults to tools/release-signing-key.pem beside this file.
import { createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const [file, sigFile, keyFile = fileURLToPath(new URL("release-signing-key.pem", import.meta.url))] =
  process.argv.slice(2);
if (!sigFile) {
  console.error("usage: node tools/verify-statement.mjs <statement.json> <statement.json.sig> [key.pem]");
  process.exit(2);
}
const signature = Buffer.from(readFileSync(sigFile, "utf8").trim(), "base64");
const ok = verify(null, readFileSync(file), createPublicKey(readFileSync(keyFile)), signature);
console.log(ok ? "Signature verified." : "The signature does NOT verify.");
process.exit(ok ? 0 : 1);
