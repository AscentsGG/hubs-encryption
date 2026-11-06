import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ClientState } from "ts-mls";
import {
  type DeviceKeyPackage,
  ciphersuite,
  frankingCommitment,
  fromBase64,
  groupConversationId,
  groupMembers,
  joinFromWelcome,
  keyPackageProblem,
  linkCheck,
  linkCode,
  loadGroup,
  openBackup,
  openLink,
  receive,
  safetyCode,
  toBase64,
  verifyDeviceCertificate,
  isStrictBase64,
} from "../src/index.js";
import {
  type GenerationTrack,
  PRIVATE_DM_MISSING_GRACE_MS,
  backupRollbackProblem,
  dueGenerations,
  messageHeader,
  trackGeneration,
  membershipProblem,
  removalCounts,
  verifyRemoval,
  verifyRemovalStatement,
} from "../src/index.js";
import {
  PRIVATE_DM_CLOCK_SKEW_MS,
  PRIVATE_DM_TIMERS,
  canonicalPayloadBytes,
  deviceCertificateBody,
  deviceRemovalBody,
  frankingStampBody,
  keyPackageLifetimeProblem,
  keyPackagePublishProblem,
  privateDmPayloadProblem,
  selfRemoveBody,
  signedRemovalsBody,
} from "../src/index.js";
import { commitmentOf, linkCodeOf, publishedLifetimeOf } from "./server-view.js";

/*
 * The cross-platform vectors for private conversations
 * (test-vectors/e2ee-test-vectors.json at the root of this repository),
 * checked against the TypeScript implementation. The Rust tests replay the
 * same file; passing it on both sides is how the two show they interoperate.
 */
const file = new URL(
  "../../test-vectors/e2ee-test-vectors.json",
  import.meta.url,
);
const v = JSON.parse(readFileSync(file, "utf8"));
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const unhex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));
const b64 = (hexText: string) => toBase64(unhex(hexText));
const te = new TextEncoder();
const x25519Pkcs8 = (seedHex: string) =>
  new Uint8Array(
    Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"),
      Buffer.from(seedHex, "hex"),
    ]),
  );

test("e2ee vectors: primitives", async () => {
  const cs = await ciphersuite();
  const p = v.primitives;
  for (const item of p.sha256)
    assert.equal(
      hex(await cs.hash.digest(te.encode(item.inputUtf8))),
      item.digestHex,
    );
  assert.equal(
    hex(
      await cs.hash.mac(
        unhex(p.hmacSha256.keyHex),
        te.encode(p.hmacSha256.messageUtf8),
      ),
    ),
    p.hmacSha256.macHex,
  );
  const prk = await cs.kdf.extract(
    unhex(p.hkdfSha256.saltHex),
    unhex(p.hkdfSha256.ikmHex),
  );
  assert.equal(hex(prk), p.hkdfSha256.prkHex);
  assert.equal(
    hex(
      await cs.kdf.expand(
        prk,
        te.encode(p.hkdfSha256.infoUtf8),
        p.hkdfSha256.length,
      ),
    ),
    p.hkdfSha256.okmHex,
  );
  const aead = p.aes128Gcm;
  assert.equal(
    hex(
      await cs.hpke.encryptAead(
        unhex(aead.keyHex),
        unhex(aead.nonceHex),
        te.encode(aead.aadUtf8),
        te.encode(aead.plaintextUtf8),
      ),
    ),
    aead.ciphertextAndTagHex,
  );
  const sig = p.ed25519;
  assert.equal(
    hex(
      await cs.signature.sign(unhex(sig.pkcs8Hex), te.encode(sig.messageUtf8)),
    ),
    sig.signatureHex,
  );
  assert.equal(
    hex(
      await cs.signature.sign(unhex(sig.seedHex), te.encode(sig.messageUtf8)),
    ),
    sig.signatureHex,
  );
  assert.ok(
    await cs.signature.verify(
      unhex(sig.publicKeyHex),
      te.encode(sig.messageUtf8),
      unhex(sig.signatureHex),
    ),
  );
  const subtle = globalThis.crypto.subtle;
  const shared = new Uint8Array(
    await subtle.deriveBits(
      {
        name: "X25519",
        public: await subtle.importKey(
          "raw",
          unhex(p.x25519.bPublicHex) as Uint8Array<ArrayBuffer>,
          { name: "X25519" },
          true,
          [],
        ),
      },
      await subtle.importKey(
        "pkcs8",
        x25519Pkcs8(p.x25519.aPrivateHex) as Uint8Array<ArrayBuffer>,
        { name: "X25519" },
        false,
        ["deriveBits"],
      ),
      256,
    ),
  );
  assert.equal(hex(shared), p.x25519.sharedSecretHex);
  const hpke = p.hpkeBase;
  const opened = await cs.hpke.open(
    await cs.hpke.importPrivateKey(unhex(hpke.recipientPrivateHex)),
    unhex(hpke.encHex),
    unhex(hpke.ciphertextHex),
    te.encode(hpke.infoUtf8),
  );
  assert.equal(new TextDecoder().decode(opened), hpke.plaintextUtf8);
});

test("e2ee vectors: Hubs constructions", async () => {
  const h = v.hubs;
  for (const d of Object.values(h.devices) as any[]) {
    const body = deviceCertificateBody(
      d.userId,
      d.deviceId,
      unhex(d.devicePublicKeyHex),
    );
    assert.equal(hex(body), d.certificateBodyHex);
    const cs = await ciphersuite();
    assert.equal(
      hex(await cs.signature.sign(unhex(d.identitySeedHex), body)),
      d.certificateHex,
    );
    assert.equal(
      JSON.stringify({
        v: 1,
        userId: d.userId,
        deviceId: d.deviceId,
        identityPublicKey: b64(d.identityPublicKeyHex),
        certificate: b64(d.certificateHex),
      }),
      d.credentialIdentityUtf8,
    );
    assert.ok(
      await verifyDeviceCertificate(
        JSON.parse(d.credentialIdentityUtf8),
        unhex(d.devicePublicKeyHex),
      ),
    );
  }
  const sc = h.safetyCode;
  assert.equal(
    await safetyCode(
      {
        userId: sc.b.userId,
        identityPublicKey: b64(sc.b.identityPublicKeyHex),
      },
      {
        userId: sc.a.userId,
        identityPublicKey: b64(sc.a.identityPublicKeyHex),
      },
    ),
    sc.code,
  );
  assert.notEqual(sc.code, sc.codeWithImposter);

  const link = h.link;
  assert.equal(await linkCode(b64(link.publicKeyHex)), link.code);
  assert.equal(linkCodeOf(b64(link.publicKeyHex)), link.code);
  assert.equal(await linkCheck(b64(link.publicKeyHex)), link.check);
  const bundle = await openLink(b64(link.privateKeyHex), link.seal.sealedJson);
  assert.equal(JSON.stringify(bundle), link.seal.bundleUtf8);

  const backup = h.backup;
  assert.equal(
    hex(createHash("sha256").update("hubs private dms backup prf v1").digest()),
    backup.prfInputHex,
  );
  const cs = await ciphersuite();
  const key = await cs.kdf.expand(
    await cs.kdf.extract(unhex(backup.saltHex), unhex(backup.prfOutputHex)),
    te.encode("hubs private dms backup v1"),
    16,
  );
  assert.equal(hex(key), backup.keyHex);
  assert.equal(
    hex(
      await cs.hpke.encryptAead(
        key,
        unhex(backup.nonceHex),
        te.encode(backup.aadUtf8),
        te.encode(backup.bundleUtf8),
      ),
    ),
    backup.ciphertextAndTagHex,
  );
  const restored = await openBackup(
    unhex(backup.prfOutputHex),
    "u_alice",
    JSON.parse(backup.storedJson),
  );
  assert.equal(JSON.stringify(restored), backup.bundleUtf8);
  await assert.rejects(
    openBackup(
      unhex(backup.prfOutputHex),
      "u_bob",
      JSON.parse(backup.storedJson),
    ),
  );

  const fr = h.franking;
  assert.equal(JSON.stringify(fr.payload), fr.payloadJsonUtf8);
  assert.equal(
    new TextDecoder().decode(canonicalPayloadBytes(fr.payload)),
    fr.canonicalBytesUtf8,
  );
  assert.equal(hex(canonicalPayloadBytes(fr.payload)), fr.canonicalBytesHex);
  assert.equal(
    hex(
      await frankingCommitment(fromBase64(fr.payload.frankingKey), fr.payload),
    ),
    fr.commitmentHex,
  );
  assert.equal(frankingStampBody(h.stamp.input), h.stamp.bodyUtf8);
  assert.equal(
    createHmac("sha256", unhex(h.stamp.keyHex))
      .update(h.stamp.bodyUtf8)
      .digest("base64"),
    h.stamp.tagBase64,
  );
});

test("e2ee vectors: payload, membership, lifetime and timer rules", () => {
  const h = v.hubs;
  for (const c of h.payloadRules)
    assert.equal(
      privateDmPayloadProblem(JSON.parse(c.payloadJson)) === null,
      c.valid,
      c.name,
    );
  // Strict base64: spare bits, missing padding and spaces are all refused.
  assert.ok(h.credentialRules.some((c: { valid: boolean }) => !c.valid));
  for (const c of h.credentialRules)
    assert.equal(isStrictBase64(c.identityPublicKey), c.valid, c.name);
  for (const c of h.membership)
    assert.equal(
      membershipProblem(c.members, { ...c.self, peer: c.peer }) === null,
      c.accepted,
      c.name,
    );
  for (const c of h.keyPackageLifetime.cases) {
    const lifetime = {
      notBefore: BigInt(c.notBefore),
      notAfter: BigInt(c.notAfter),
    };
    assert.equal(
      keyPackageLifetimeProblem(lifetime, c.atSeconds * 1000) === null,
      c.adderAccepts,
      c.name,
    );
    assert.equal(
      keyPackagePublishProblem(lifetime, c.atSeconds * 1000) === null,
      c.serverStores,
      c.name,
    );
  }
  assert.deepEqual(
    h.timers,
    PRIVATE_DM_TIMERS.map((t) => t.seconds),
  );
  assert.equal(h.clockSkewMs, PRIVATE_DM_CLOCK_SKEW_MS);
});

test("e2ee vectors: signed device removals and the removal rule", async () => {
  const r = v.hubs.deviceRemoval;
  const cs = await ciphersuite();
  const alice = v.hubs.devices.alice;
  const identityPkcs8 = unhex(
    "302e020100300506032b657004220420" + alice.identitySeedHex,
  );
  const devicePkcs8 = unhex(
    "302e020100300506032b657004220420" + alice.deviceSeedHex,
  );
  const removal = r.identityRemoval;
  const body = deviceRemovalBody(
    removal.userId,
    removal.deviceId,
    unhex(removal.devicePublicKeyHex),
    removal.at,
  );
  assert.equal(hex(body), removal.bodyHex);
  assert.equal(
    hex(await cs.signature.sign(identityPkcs8, body)),
    removal.signatureHex,
  );
  const self = r.selfRemoval;
  const selfBody = selfRemoveBody(self.userId, self.deviceId, self.at);
  assert.equal(hex(selfBody), self.bodyHex);
  assert.equal(
    hex(await cs.signature.sign(devicePkcs8, selfBody)),
    self.signatureHex,
  );
  const statement = r.signedRemovalsStatement;
  const statementBody = signedRemovalsBody(
    statement.userId,
    unhex(statement.identityPublicKeyHex),
  );
  assert.equal(hex(statementBody), statement.bodyHex);
  assert.equal(
    hex(await cs.signature.sign(identityPkcs8, statementBody)),
    statement.signatureHex,
  );
  assert.equal(
    await verifyRemovalStatement({
      userId: statement.userId,
      identityKey: b64(statement.identityPublicKeyHex),
      signature: b64(statement.signatureHex),
    }),
    statement.verifies,
  );
  for (const c of r.verifyCases)
    assert.equal(await verifyRemoval(c.member, c.proof), c.valid, c.name);
  for (const c of r.rule)
    assert.equal(
      removalCounts(c),
      c.removes,
      `${c.proof} ${c.startedOver} ${c.signedRemovals}`,
    );
});

test("e2ee vectors: the passkey backup with its counter, and the rollback rule", async () => {
  const c = v.hubs.backupCounter;
  const bundle = await openBackup(unhex(c.prfOutputHex), "u_alice", {
    salt: b64(c.saltHex),
    nonce: b64(c.nonceHex),
    ciphertext: b64(c.ciphertextAndTagHex),
  });
  assert.equal(JSON.stringify(bundle), c.bundleUtf8);
  assert.equal(bundle.counter, 3);
  for (const r of c.rule)
    assert.equal(
      backupRollbackProblem(r.counter ?? undefined, r.seen) === null,
      r.restores,
      JSON.stringify(r),
    );
});

test("e2ee vectors: missing messages, from generations to the notice rule", async () => {
  const g = v.mls.generations;
  const bobState = await joinFromWelcome(
    b64(g.welcomeHex),
    keyPackage(g.keyPackage),
  );
  for (const message of g.messages)
    assert.deepEqual(
      await messageHeader(bobState, b64(message.mlsMessageHex)),
      {
        epoch: message.epoch,
        leafIndex: message.senderLeafIndex,
        generation: message.generation,
      },
    );
  const rule = v.hubs.missingMessages;
  assert.equal(rule.graceMs, PRIVATE_DM_MISSING_GRACE_MS);
  for (const c of rule.cases) {
    let track: GenerationTrack = {
      userId: "u_alice",
      next: 0,
      gaps: [],
      told: [],
    };
    c.steps.forEach((step: any, index: number) => {
      if ("arrive" in step) {
        const result = trackGeneration(track, step.arrive, step.at, step.at);
        track = result.track;
        assert.equal(result.settled !== null, step.settles, c.name);
      } else {
        const result = dueGenerations(track, step.tell, `notice-${index}`);
        track = result.track;
        assert.deepEqual(
          result.due.map((d) => d.generation),
          step.missing,
          c.name,
        );
      }
    });
  }
});

test("e2ee vectors: one last-resort key package opens two welcomes", async () => {
  const l = v.mls.lastResort;
  const pkg = keyPackage(l.keyPackage);
  for (const welcome of l.welcomes) {
    const joined = await joinFromWelcome(b64(welcome.welcomeHex), pkg);
    assert.equal(groupConversationId(joined), welcome.conversationId);
    assert.equal(Number(joined.groupContext.epoch), welcome.epochAfter);
    assert.deepEqual(
      groupMembers(joined).map(
        (m) => `${m.userId}/${m.deviceId}@${m.leafIndex}`,
      ),
      welcome.membersAfter,
    );
  }
});

const keyPackage = (k: any): DeviceKeyPackage => ({
  id: k.id,
  publicPackage: b64(k.mlsMessageHex),
  privatePackage: JSON.stringify({
    initPrivateKey: b64(k.initPrivateKeyHex),
    hpkePrivateKey: b64(k.encryptionPrivateKeyHex),
    signaturePrivateKey: b64(k.signaturePrivateKeyPkcs8Hex),
  }),
});

test("e2ee vectors: MLS conversation, replayed by each receiver in order", async () => {
  const m = v.mls;
  const nowMs = v.generator.nowSeconds * 1000 + 600_000;
  for (const k of Object.values(m.keyPackages) as any[]) {
    assert.equal(keyPackageProblem(b64(k.mlsMessageHex), nowMs), null);
    assert.ok(publishedLifetimeOf(b64(k.mlsMessageHex)));
  }
  const states: Record<string, ClientState | undefined> = {};
  const members = (state: ClientState) =>
    groupMembers(state).map((x) => `${x.userId}/${x.deviceId}@${x.leafIndex}`);
  const self = {
    device_alice_1: {
      userId: "u_alice",
      identityPublicKey: b64(v.hubs.devices.alice.identityPublicKeyHex),
      peer: "u_bob",
    },
    device_bob_1: {
      userId: "u_bob",
      identityPublicKey: b64(v.hubs.devices.bob.identityPublicKeyHex),
      peer: "u_alice",
    },
  } as Record<string, Parameters<typeof membershipProblem>[1]>;
  let checked = 0;
  for (const step of m.steps) {
    for (const receiver of step.receivers ?? []) {
      if (step.receiverStateHex)
        states[receiver] = loadGroup(b64(step.receiverStateHex));
      const state = states[receiver];
      if (step.type === "message") {
        assert.ok(state, `${step.step}: ${receiver} has joined`);
        const ciphertext = b64(step.mlsMessageHex);
        assert.equal(commitmentOf(ciphertext), b64(step.authenticatedDataHex));
        const result = await receive(state!, ciphertext);
        assert.equal(result.kind, "message", step.step);
        if (result.kind !== "message") continue;
        assert.deepEqual(result.payload, step.payload, step.step);
        assert.equal(JSON.stringify(result.payload), step.plaintextUtf8);
        assert.equal(result.sender.deviceId, step.sender);
        states[receiver] = result.state;
      } else if (step.type === "commit") {
        assert.ok(state, `${step.step}: ${receiver} has joined`);
        const result = await receive(state!, b64(step.commitHex));
        assert.equal(result.kind, "change", step.step);
        if (result.kind !== "change") continue;
        assert.equal(Number(result.state.groupContext.epoch), step.epochAfter);
        assert.equal(
          membershipProblem(groupMembers(result.state), self[receiver]),
          null,
        );
        if (step.membersAfter)
          assert.deepEqual(members(result.state), step.membersAfter);
        result.release();
        states[receiver] = result.state;
      } else if (step.type === "commit+welcome") {
        if (state) {
          const result = await receive(state, b64(step.commitHex));
          assert.equal(result.kind, "change", step.step);
          if (result.kind === "change") {
            assert.deepEqual(members(result.state), step.membersAfter);
            result.release();
            states[receiver] = result.state;
          }
        }
      } else if (step.type === "refuse") {
        assert.ok(state);
        await assert.rejects(
          receive(state!, b64(step.mlsMessageHex)),
          step.step,
        );
      } else if (step.type === "refuseMembership") {
        assert.ok(state);
        const result = await receive(state!, b64(step.commitHex));
        assert.equal(result.kind, "change");
        assert.deepEqual(members(result.state), step.membersAfter);
        assert.equal(
          membershipProblem(groupMembers(result.state), self[receiver]),
          step.membershipError,
        );
        // Refused: the receiver keeps the state it had.
      } else if (step.type === "refuseWelcome") {
        const joined = await joinFromWelcome(
          b64(step.welcomeHex),
          keyPackage(m.keyPackages.bobSpare),
        );
        assert.equal(groupConversationId(joined), step.groupIdUtf8);
        assert.notEqual(groupConversationId(joined), m.conversationId);
      }
      checked++;
    }
    if (step.welcomeHex && step.type === "commit+welcome") {
      const name = step.welcomeFor.device === "device_bob_1" ? "bob" : "bob2";
      const joined = await joinFromWelcome(
        b64(step.welcomeHex),
        keyPackage(m.keyPackages[name]),
      );
      assert.equal(groupConversationId(joined), m.conversationId);
      assert.equal(hex(te.encode(groupConversationId(joined))), m.groupIdHex);
      assert.deepEqual(members(joined), step.membersAfter);
      states[step.welcomeFor.device] = joined;
      checked++;
    }
    for (const receiver of step.notReadableBy ?? []) {
      await assert.rejects(receive(states[receiver]!, b64(step.mlsMessageHex)));
      checked++;
    }
  }
  assert.ok(checked >= 25, `checked ${checked} receives`);
});

test("e2ee vectors: calls (protocol 3), through the web's call code", async () => {
  const calls = await import("../src/index.js");
  const c = v.calls;
  const base64Url = (bytes: Uint8Array) =>
    Buffer.from(bytes).toString("base64url");
  const p256 = (scalarHex: string, publicKeyHex: string) => {
    const pub = unhex(publicKeyHex);
    return globalThis.crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        d: base64Url(unhex(scalarHex)),
        x: base64Url(pub.subarray(1, 33)),
        y: base64Url(pub.subarray(33, 65)),
      },
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"],
    );
  };
  const connection = (b: any) => ({
    leaseId: b.leaseId,
    userId: b.userId,
    publicKey: b64(b.connectionPublicKeyHex),
    v: 3,
    binding: b.json,
  });
  // Bindings: the exact body, a verifying signature and certificate.
  for (const name of ["alice", "bob"]) {
    const b = c.bindings[name];
    assert.equal(
      hex(
        calls.callBindingBody({
          channelId: b.channelId,
          leaseId: b.leaseId,
          userId: b.userId,
          deviceId: b.deviceId,
          identityPublicKey: unhex(b.identityPublicKeyHex),
          devicePublicKey: unhex(b.devicePublicKeyHex),
          connectionPublicKey: unhex(b.connectionPublicKeyHex),
        }),
      ),
      b.bindingBodyHex,
    );
    assert.equal(
      (await calls.checkCallBinding(b.channelId, connection(b))).status,
      "valid",
    );
    assert.equal(
      hex(await calls.callConnectionHash(b.channelId, connection(b))),
      b.hashHex,
    );
  }
  for (const item of c.refusedBindings)
    assert.equal(
      (
        await calls.checkCallBinding(item.channelId, {
          leaseId: item.leaseId,
          userId: item.userId,
          publicKey: b64(item.connectionPublicKeyHex),
          v: 3,
          binding: item.json,
        })
      ).status,
      "invalid",
      item.name,
    );
  assert.equal(
    hex(
      await calls.callConnectionHash(c.channelId, {
        leaseId: c.unbound.carol.leaseId,
        userId: c.unbound.carol.userId,
        publicKey: b64(c.unbound.carol.connectionPublicKeyHex),
        v: 3,
        binding: null,
      }),
    ),
    c.unbound.carol.hashHex,
  );
  // The wrap opens both ways, and never under a changed info.
  const alice = await p256(
    c.wrap.aliceToBob.senderScalarHex,
    c.bindings.alice.connectionPublicKeyHex,
  );
  const bob = await p256(
    c.wrap.aliceToBob.recipientScalarHex,
    c.bindings.bob.connectionPublicKeyHex,
  );
  for (const [w, sender, recipient, senderPublic] of [
    [c.wrap.aliceToBob, alice, bob, c.bindings.alice.connectionPublicKeyHex],
    [c.wrap.bobToAlice, bob, alice, c.bindings.bob.connectionPublicKeyHex],
  ] as const) {
    const info = unhex(w.infoHex);
    const sealed = await calls.wrapCallKeyV3(
      unhex(w.callKeyHex),
      sender,
      b64(
        senderPublic === c.bindings.alice.connectionPublicKeyHex
          ? c.bindings.bob.connectionPublicKeyHex
          : c.bindings.alice.connectionPublicKeyHex,
      ),
      info,
      unhex(w.ivHex),
    );
    assert.equal(hex(Buffer.from(sealed.wrapped, "base64")), w.sealedHex);
    assert.equal(
      hex(
        await calls.unwrapCallKeyV3(sealed, recipient, b64(senderPublic), info),
      ),
      w.callKeyHex,
    );
  }
  const aliceToBob = {
    wrapped: b64(c.wrap.aliceToBob.sealedHex),
    iv: b64(c.wrap.aliceToBob.ivHex),
  };
  for (const bad of c.wrap.mustNotOpen)
    await assert.rejects(
      calls.unwrapCallKeyV3(
        aliceToBob,
        bob,
        b64(c.bindings.alice.connectionPublicKeyHex),
        unhex(bad.infoHex),
      ),
      () => true,
      bad.name,
    );
  // Codes and the roster statement.
  const callKey = unhex(c.callKeyHex);
  for (const name of ["twoPeople", "threePeople"]) {
    const code = c.code[name];
    const transcript = calls.callCodeTranscript({
      channelId: code.channelId,
      epoch: c.epoch,
      keyIndex: c.keyIndex,
      hashes: code.hashesHex.map(unhex),
    });
    assert.equal(hex(transcript), code.transcriptHex);
    assert.equal(await calls.callCodeV3(callKey, transcript), code.code);
  }
  assert.equal(
    await calls.compareCallView({
      channelId: c.view.channelId,
      leaseId: c.view.leaseId,
      devicePublicKey: b64(c.view.devicePublicKeyHex),
      view: {
        epoch: c.view.epoch,
        keyIndex: c.view.keyIndex,
        digest: b64(c.view.transcriptDigestHex),
        signature: b64(c.view.signatureHex),
      },
      epoch: c.epoch,
      keyIndex: c.keyIndex,
      transcriptDigest: unhex(c.view.transcriptDigestHex),
    }),
    "same",
  );
  // The older code, kept while an older app is in the call.
  assert.equal(
    await calls.callCodeV2(
      c.epoch,
      [
        b64(c.bindings.alice.connectionPublicKeyHex),
        b64(c.bindings.bob.connectionPublicKeyHex),
      ],
      callKey,
    ),
    c.code.v2.code,
  );
  // Every policy case, and the lists in order.
  for (const item of c.policy)
    assert.deepEqual(
      calls.callPeerDecision(item.input),
      item.expected,
      item.name,
    );
  for (const item of c.policyLists)
    assert.deepEqual(
      calls.callPeerDecisions(item.inputs),
      item.expected,
      item.name,
    );
});
