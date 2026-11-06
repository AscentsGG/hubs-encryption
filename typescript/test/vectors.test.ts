import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  ciphersuite,
  frankingCommitment,
  fromBase64,
  linkCheck,
  linkCode,
  openBackup,
  openLink,
  safetyCode,
  toBase64,
  verifyDeviceCertificate,
} from "../src/index.js";
import {
  canonicalPayloadBytes,
  deviceCertificateBody,
  frankingStampBody,
} from "../src/index.js";
import {
  callCodeV2 as verificationCode,
  callWrapContextV2 as wrapContext,
} from "../src/index.js";
import { linkCodeOf } from "./server-view.js";

/*
 * Known-answer vectors for every Hubs-specific construction around MLS and
 * encrypted calls (test-vectors/test-vectors.json at the root of this
 * repository). MLS itself is covered
 * by ts-mls's RFC 9420 test vectors; these pin our own formats so an outside
 * reviewer, or a second implementation, can check them byte for byte.
 */
const vectors = JSON.parse(
  readFileSync(
    new URL("../../test-vectors/test-vectors.json", import.meta.url),
    "utf8",
  ),
);
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

test("vectors: device certificate body and its Ed25519 signature", async () => {
  const v = vectors.deviceCertificate;
  const body = deviceCertificateBody(
    v.userId,
    v.deviceId,
    Buffer.from(v.devicePublicKeyHex, "hex"),
  );
  assert.equal(hex(body), v.bodyHex);
  const cs = await ciphersuite();
  const signature = await cs.signature.sign(
    Buffer.from(v.identityPrivateSeedHex, "hex"),
    body,
  );
  assert.equal(hex(signature), v.ed25519SignatureHex);
  assert.equal(
    await verifyDeviceCertificate(
      {
        v: 1,
        userId: v.userId,
        deviceId: v.deviceId,
        identityPublicKey: toBase64(Buffer.from(v.identityPublicKeyHex, "hex")),
        certificate: toBase64(signature),
      },
      Buffer.from(v.devicePublicKeyHex, "hex"),
    ),
    true,
  );
  // The same certificate for another account or device does not check out.
  assert.equal(
    await verifyDeviceCertificate(
      {
        v: 1,
        userId: "u_mallory",
        deviceId: v.deviceId,
        identityPublicKey: toBase64(Buffer.from(v.identityPublicKeyHex, "hex")),
        certificate: toBase64(signature),
      },
      Buffer.from(v.devicePublicKeyHex, "hex"),
    ),
    false,
  );
});

test("vectors: safety code, both ways round", async () => {
  const v = vectors.safetyCode;
  assert.equal(await safetyCode(v.a, v.b), v.code);
  assert.equal(await safetyCode(v.b, v.a), v.code);
  assert.match(v.code, /^(\d{5} ){11}\d{5}$/);
});

test("vectors: link code (device and server agree) and link check", async () => {
  const v = vectors.link;
  assert.equal(await linkCode(v.publicKey), v.code);
  assert.equal(linkCodeOf(v.publicKey), v.code);
  assert.equal(await linkCheck(v.publicKey), v.check);
});

test("vectors: the HPKE link hand-off and the passkey backup open to their bundles", async () => {
  assert.deepEqual(
    await openLink(vectors.linkSeal.privateKey, vectors.linkSeal.sealed),
    vectors.linkSeal.opensTo,
  );
  const b = vectors.backup;
  const prf = Buffer.from(b.prfOutputHex, "hex");
  assert.deepEqual(await openBackup(prf, b.userId, b.sealed), b.opensTo);
  // Bound to the account: the same backup does not open for another one.
  await assert.rejects(openBackup(prf, "u_mallory", b.sealed));
});

test("vectors: franking commitment and the server's stamp", async () => {
  const v = vectors.franking;
  assert.equal(
    Buffer.from(canonicalPayloadBytes(v.payload)).toString("utf8"),
    v.canonicalBytesUtf8,
  );
  const commitment = await frankingCommitment(
    fromBase64(v.payload.frankingKey),
    v.payload,
  );
  assert.equal(toBase64(commitment), v.commitmentBase64);
  // The server recomputes the commitment with node:crypto when a report arrives.
  assert.equal(
    createHmac("sha256", fromBase64(v.payload.frankingKey))
      .update(canonicalPayloadBytes(v.payload))
      .digest("base64"),
    v.commitmentBase64,
  );
  assert.equal(frankingStampBody(v.stampInput), v.stampBody);
  assert.equal(
    createHmac("sha256", Buffer.from(v.stampKeyHex, "hex"))
      .update(v.stampBody)
      .digest("base64"),
    v.stampBase64,
  );
});

test("vectors: encrypted call code and wrap context", async () => {
  const v = vectors.callCode;
  assert.equal(
    await verificationCode(
      v.epoch,
      v.publicKeys,
      Buffer.from(v.callKeyHex, "hex"),
    ),
    v.code,
  );
  assert.equal(
    await verificationCode(
      v.epoch,
      [...v.publicKeys].reverse(),
      Buffer.from(v.callKeyHex, "hex"),
    ),
    v.code,
  );
  assert.equal(wrapContext("dm-channel-1", v.epoch), v.wrapContext);
});
