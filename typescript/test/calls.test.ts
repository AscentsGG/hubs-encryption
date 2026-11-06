import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  type CallConnection,

  type PrivateDmApi,
  PrivateDmClient,
  callBindingBody,
  callCodeKey,
  callCodeMac,
  callCodeTranscript,
  callCodeV2,
  callCodeV3,
  callConnectionHash,
  callPairVersion,
  callPeerDecision,
  callPeerDecisions,
  callSharedSecret,
  callStatement,
  callTranscriptDigest,
  callUnboundBody,
  callViewBody,
  callWrapContextV2,
  callWrapInfo,
  callWrapKey,
  checkCallBinding,
  compareCallView,
  createDevice,
  createIdentity,
  deviceCertificateBody,
  lengthPrefixed,
  makeCallKey,
  makeConnectionKeys,
  memoryStore,
  signCallBinding,
  signCallView,
  unwrapCallKeyV2,
  unwrapCallKeyV3,
  validCallPublicKey,
  wrapCallKeyV2,
  wrapCallKeyV3,
} from "../src/index.js";

/*
 * Calls, protocol 3: every format against the known answers in
 * call-vectors.json (made by the same generator as the private
 * conversation vectors), the rule for who gets the call key, and what the
 * client records in its trust store.
 */
const v = JSON.parse(
  readFileSync(new URL("./call-vectors.json", import.meta.url), "utf8"),
);
const te = new TextEncoder();
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const unhex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));
const b64 = (hexText: string) => Buffer.from(hexText, "hex").toString("base64");
const base64Url = (bytes: Uint8Array) =>
  Buffer.from(bytes).toString("base64url");

/** A P-256 private key from a vector's scalar and public key. */
const connectionKey = (scalarHex: string, publicKeyHex: string) => {
  const publicKey = unhex(publicKeyHex);
  return globalThis.crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      d: base64Url(unhex(scalarHex)),
      x: base64Url(publicKey.subarray(1, 33)),
      y: base64Url(publicKey.subarray(33, 65)),
    },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
};
const connectionOf = (binding: any): CallConnection => ({
  leaseId: binding.leaseId,
  userId: binding.userId,
  publicKey: b64(binding.connectionPublicKeyHex),
  v: 3,
  binding: binding.json,
});
const ed25519Pkcs8 = (seedHex: string) =>
  Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex"),
  ]).toString("base64");

test("calls: bindings are the bytes the vectors list, and verify", async () => {
  for (const name of ["alice", "bob"]) {
    const b = v.bindings[name];
    const body = callBindingBody({
      channelId: b.channelId,
      leaseId: b.leaseId,
      userId: b.userId,
      deviceId: b.deviceId,
      identityPublicKey: unhex(b.identityPublicKeyHex),
      devicePublicKey: unhex(b.devicePublicKeyHex),
      connectionPublicKey: unhex(b.connectionPublicKeyHex),
    });
    assert.equal(hex(body), b.bindingBodyHex, name);
    assert.equal(
      hex(
        deviceCertificateBody(
          b.userId,
          b.deviceId,
          unhex(b.devicePublicKeyHex),
        ),
      ),
      b.certificateBodyHex,
    );
    // Signing is deterministic: the same seed signs the same bytes.
    const signed = await signCallBinding(
      {
        userId: b.userId,
        deviceId: b.deviceId,
        identityPublicKey: b64(b.identityPublicKeyHex),
        publicKey: b64(b.devicePublicKeyHex),
        signKey: ed25519Pkcs8(b.deviceSeedHex),
        certificate: b64(b.certificateHex),
      },
      {
        channelId: b.channelId,
        leaseId: b.leaseId,
        connectionPublicKey: b64(b.connectionPublicKeyHex),
      },
    );
    assert.deepEqual(signed, b.json);
    assert.equal(hex(Buffer.from(signed.signature, "base64")), b.signatureHex);
    const connection = connectionOf(b);
    assert.equal(hex(callStatement(b.channelId, connection)), b.bindingBodyHex);
    assert.equal(
      hex(await callConnectionHash(b.channelId, connection)),
      b.hashHex,
    );
    assert.deepEqual(await checkCallBinding(b.channelId, connection), {
      status: "valid",
      identityPublicKey: b64(b.identityPublicKeyHex),
      devicePublicKey: b64(b.devicePublicKeyHex),
    });
  }
  // Each listed change makes the binding fail.
  assert.ok(v.refusedBindings.length >= 5);
  for (const item of v.refusedBindings) {
    const connection: CallConnection = {
      leaseId: item.leaseId,
      userId: item.userId,
      publicKey: b64(item.connectionPublicKeyHex),
      v: 3,
      binding: item.json,
    };
    assert.deepEqual(
      await checkCallBinding(item.channelId, connection),
      { status: "invalid" },
      item.name,
    );
    assert.equal(
      hex(callStatement(item.channelId, connection)),
      item.statementHex,
      item.name,
    );
  }
  // No binding at all.
  assert.deepEqual(
    await checkCallBinding(v.channelId, {
      ...connectionOf(v.bindings.alice),
      binding: null,
    }),
    { status: "none" },
  );
});

test("calls: the unbound statement and its hash", async () => {
  const c = v.unbound.carol;
  const body = callUnboundBody({
    channelId: c.channelId,
    leaseId: c.leaseId,
    userId: c.userId,
    connectionPublicKey: unhex(c.connectionPublicKeyHex),
  });
  assert.equal(hex(body), c.statementHex);
  assert.equal(
    hex(
      await callConnectionHash(c.channelId, {
        leaseId: c.leaseId,
        userId: c.userId,
        publicKey: b64(c.connectionPublicKeyHex),
        v: 3,
        binding: null,
      }),
    ),
    c.hashHex,
  );
  // Strings: length-prefixed, at most 255 bytes, well-formed only.
  assert.deepEqual([...lengthPrefixed("ab")], [0, 2, 97, 98]);
  assert.throws(() => lengthPrefixed("x".repeat(256)), /too long/);
  assert.doesNotThrow(() => lengthPrefixed("x".repeat(255)));
  assert.throws(() => lengthPrefixed("\ud800"), /well-formed/);
});

test("calls: the wrap opens only for its pair, call, epoch, slot and statements", async () => {
  for (const name of ["aliceToBob", "bobToAlice", "aliceToCarol"]) {
    const w = v.wrap[name];
    const senderPublic =
      name === "bobToAlice"
        ? v.bindings.bob.connectionPublicKeyHex
        : v.bindings.alice.connectionPublicKeyHex;
    const recipientPublic =
      name === "aliceToBob"
        ? v.bindings.bob.connectionPublicKeyHex
        : name === "bobToAlice"
          ? v.bindings.alice.connectionPublicKeyHex
          : v.unbound.carol.connectionPublicKeyHex;
    const sender = await connectionKey(w.senderScalarHex, senderPublic);
    const recipient = await connectionKey(w.recipientScalarHex, recipientPublic);
    const info = callWrapInfo({
      channelId: v.channelId,
      epoch: v.epoch,
      keyIndex: v.keyIndex,
      senderHash: unhex(w.senderHashHex),
      recipientHash: unhex(w.recipientHashHex),
    });
    assert.equal(hex(info), w.infoHex, name);
    assert.equal(
      hex(await callSharedSecret(sender, b64(recipientPublic))),
      w.sharedSecretHex,
    );
    assert.equal(
      hex(await callWrapKey(sender, b64(recipientPublic), info)),
      w.wrapKeyHex,
    );
    const sealed = await wrapCallKeyV3(
      unhex(w.callKeyHex),
      sender,
      b64(recipientPublic),
      info,
      unhex(w.ivHex),
    );
    assert.equal(hex(Buffer.from(sealed.wrapped, "base64")), w.sealedHex);
    assert.equal(sealed.wrapped.length, 64, "the column sizes stay");
    assert.equal(sealed.iv.length, 16);
    assert.equal(
      hex(await unwrapCallKeyV3(sealed, recipient, b64(senderPublic), info)),
      w.callKeyHex,
    );
    if (name !== "aliceToBob") continue;
    for (const bad of v.wrap.mustNotOpen)
      await assert.rejects(
        unwrapCallKeyV3(sealed, recipient, b64(senderPublic), unhex(bad.infoHex)),
        () => true,
        bad.name,
      );
    // Another connection cannot open it.
    const other = await makeConnectionKeys();
    await assert.rejects(
      unwrapCallKeyV3(sealed, other.privateKey, b64(senderPublic), info),
    );
  }
  // Protocol 2 for a pair with an older app.
  const w2 = v.wrapV2;
  const alice = await connectionKey(
    v.wrap.aliceToBob.senderScalarHex,
    v.bindings.alice.connectionPublicKeyHex,
  );
  const bob = await connectionKey(
    v.wrap.aliceToBob.recipientScalarHex,
    v.bindings.bob.connectionPublicKeyHex,
  );
  assert.equal(w2.contextUtf8, callWrapContextV2(v.channelId, v.epoch));
  const sealed = await wrapCallKeyV2(
    unhex(v.callKeyHex),
    alice,
    b64(v.bindings.bob.connectionPublicKeyHex),
    w2.contextUtf8,
    unhex(w2.ivHex),
  );
  assert.equal(hex(Buffer.from(sealed.wrapped, "base64")), w2.sealedHex);
  assert.equal(
    hex(
      await unwrapCallKeyV2(
        sealed,
        bob,
        b64(v.bindings.alice.connectionPublicKeyHex),
        w2.contextUtf8,
      ),
    ),
    v.callKeyHex,
  );
  // The two versions never open each other's copies.
  await assert.rejects(
    unwrapCallKeyV3(
      sealed,
      bob,
      b64(v.bindings.alice.connectionPublicKeyHex),
      unhex(v.wrap.aliceToBob.infoHex),
    ),
  );
});

test("calls: the Call code for two and three people, and the older code", async () => {
  const callKey = unhex(v.callKeyHex);
  assert.equal(hex(await callCodeKey(callKey)), v.code.codeKeyHex);
  for (const name of ["twoPeople", "threePeople"]) {
    const c = v.code[name];
    const transcript = callCodeTranscript({
      channelId: c.channelId,
      epoch: v.epoch,
      keyIndex: v.keyIndex,
      // Given in any order: the transcript sorts them.
      hashes: [...c.hashesHex].reverse().map(unhex),
    });
    assert.equal(hex(transcript), c.transcriptHex, name);
    assert.equal(
      hex(await callTranscriptDigest(transcript)),
      c.transcriptDigestHex,
    );
    assert.equal(hex(await callCodeMac(callKey, transcript)), c.macHex);
    assert.equal(await callCodeV3(callKey, transcript), c.code);
    assert.match(c.code, /^\d{5} \d{5} \d{5} \d{5}$/);
    // Another call key gives another code.
    assert.notEqual(await callCodeV3(makeCallKey(), transcript), c.code);
  }
  assert.equal(
    await callCodeV2(
      v.epoch,
      [
        b64(v.bindings.bob.connectionPublicKeyHex),
        b64(v.bindings.alice.connectionPublicKeyHex),
      ],
      callKey,
    ),
    v.code.v2.code,
  );
});

test("calls: roster statements", async () => {
  const r = v.view;
  const digest = unhex(r.transcriptDigestHex);
  const body = callViewBody({
    channelId: r.channelId,
    leaseId: r.leaseId,
    epoch: r.epoch,
    keyIndex: r.keyIndex,
    transcriptDigest: digest,
  });
  assert.equal(hex(body), r.bodyHex);
  const signed = await signCallView(ed25519Pkcs8(v.bindings.alice.deviceSeedHex), {
    channelId: r.channelId,
    leaseId: r.leaseId,
    epoch: r.epoch,
    keyIndex: r.keyIndex,
    transcriptDigest: digest,
  });
  assert.equal(hex(Buffer.from(signed.signature, "base64")), r.signatureHex);
  const compare = (view: any, mine = digest, leaseId = r.leaseId) =>
    compareCallView({
      channelId: r.channelId,
      leaseId,
      devicePublicKey: b64(r.devicePublicKeyHex),
      view,
      epoch: r.epoch,
      keyIndex: r.keyIndex,
      transcriptDigest: mine,
    });
  assert.equal(await compare(signed), "same");
  assert.equal(await compare(signed, new Uint8Array(32)), "different");
  // A statement relabeled to another connection, an older epoch, or none.
  assert.equal(await compare(signed, digest, "lease-bob-1"), "missing");
  assert.equal(await compare({ ...signed, epoch: "other" }), "missing");
  assert.equal(await compare(null), "missing");
  assert.equal(
    await compare({ ...signed, digest: Buffer.alloc(32).toString("base64") }),
    "missing",
    "a digest the device key never signed",
  );
});

test("calls: every policy case in the vectors, and what each rule means", () => {
  for (const item of v.policy)
    assert.deepEqual(callPeerDecision(item.input), item.expected, item.name);
  for (const item of v.policyLists)
    assert.deepEqual(callPeerDecisions(item.inputs), item.expected, item.name);
  const by = (name: string) =>
    v.policy.find((item: any) => item.name === name).expected;
  // Spelled out here too, so a regenerated file cannot drift from the rule.
  assert.equal(by("a binding that does not verify").state, "refused");
  assert.equal(by("a third account in a one-to-one call").state, "refused");
  assert.equal(by("you, bound under another identity key").state, "refused");
  assert.equal(by("you, bound under your identity key").state, "you-linked");
  // Your own account on a device that isn't linked: a linked device lets it
  // in only when it cannot tell (it has no identity either).
  assert.deepEqual(by("you, unbound"), {
    state: "refused",
    share: false,
    pin: "none",
    refusal: "own-unlinked",
  });
  assert.equal(by("you, on an older app").refusal, "own-unlinked");
  assert.equal(by("you, unbound, in a one-to-one call").refusal, "own-unlinked");
  assert.deepEqual(by("you, unbound, on a device with no identity"), {
    state: "you-unlinked",
    share: true,
    pin: "none",
  });
  assert.equal(
    by("you, on an older app, on a device with no identity").state,
    "you-unlinked",
  );
  assert.deepEqual(by("another account, bound, first sight"), {
    state: "not-verified",
    share: true,
    pin: "first",
  });
  assert.equal(by("another account, pinned and verified").state, "verified");
  assert.deepEqual(
    by("another account under a new identity key, verified before"),
    { state: "held", share: false, pin: "changed" },
  );
  assert.deepEqual(
    by("another account under a new identity key, not verified before"),
    { state: "changed", share: true, pin: "changed" },
  );
  assert.equal(by("another account, unbound, verified").state, "held");
  assert.equal(by("another account on an older app, not verified").share, true);
  assert.equal(by("an older app after the old path closed").state, "refused");
  assert.equal(callPairVersion(3, 3), 3);
  assert.equal(callPairVersion(3, 2), 2);
  assert.equal(callPairVersion(undefined, 3), 2);
});

test("calls: connection keys are P-256, made non-extractable, for deriving bits only", async () => {
  const keys = await makeConnectionKeys();
  assert.ok(validCallPublicKey(keys.publicKey));
  assert.equal(keys.privateKey.extractable, false);
  assert.deepEqual(keys.privateKey.usages, ["deriveBits"]);
  assert.equal(validCallPublicKey("A".repeat(88)), false);
  // A second spelling of the same bytes (unused low bits set) is refused.
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const last = alphabet.indexOf(keys.publicKey[86]);
  const respelled = `${keys.publicKey.slice(0, 86)}${alphabet[last ^ 1]}=`;
  assert.deepEqual(
    Buffer.from(respelled, "base64"),
    Buffer.from(keys.publicKey, "base64"),
  );
  assert.equal(validCallPublicKey(respelled), false);
});

/* ---------- The client's part ---------- */

function noServer(): PrivateDmApi {
  return async () => {
    throw new Error("No server in this test.");
  };
}
async function deviceFor(userId: string, deviceId: string) {
  const identity = await createIdentity();
  const device = await createDevice(identity, userId, deviceId);
  return { identity, device };
}
async function clientWith(userId: string, setup?: Awaited<ReturnType<typeof deviceFor>>) {
  const store = memoryStore();
  let now = 1_000;
  const client = new PrivateDmClient(noServer(), store, userId, () => now++, {
    locks: null,
  });
  if (setup) {
    await store.set("identity", setup.identity);
    await store.set("device", setup.device);
    await store.set("trusted", { [userId]: setup.identity.publicKey });
  }
  return { client, store };
}
async function boundConnection(
  channelId: string,
  leaseId: string,
  setup: Awaited<ReturnType<typeof deviceFor>>,
): Promise<CallConnection> {
  const keys = await makeConnectionKeys();
  return {
    leaseId,
    userId: setup.device.userId,
    publicKey: keys.publicKey,
    v: 3,
    binding: await signCallBinding(setup.device, {
      channelId,
      leaseId,
      connectionPublicKey: keys.publicKey,
    }),
  };
}

test("calls client: a binding needs a device, and is signed for this connection", async () => {
  const none = await clientWith("u_alice");
  const keys = await makeConnectionKeys();
  assert.equal(await none.client.callBinding("c1", "l1", keys.publicKey), null);
  const alice = await deviceFor("u_alice", "d_alice");
  const { client } = await clientWith("u_alice", alice);
  const binding = await client.callBinding("c1", "l1", keys.publicKey);
  assert.ok(binding);
  assert.equal(binding.deviceId, "d_alice");
  const connection = {
    leaseId: "l1",
    userId: "u_alice",
    publicKey: keys.publicKey,
    v: 3,
    binding,
  };
  assert.equal((await checkCallBinding("c1", connection)).status, "valid");
  assert.equal((await checkCallBinding("c2", connection)).status, "invalid");
  const view = await client.callView({
    channelId: "c1",
    leaseId: "l1",
    epoch: "e1",
    keyIndex: 0,
    transcriptDigest: new Uint8Array(32).fill(7),
  });
  assert.equal(
    await compareCallView({
      channelId: "c1",
      leaseId: "l1",
      devicePublicKey: binding.devicePublicKey,
      view,
      epoch: "e1",
      keyIndex: 0,
      transcriptDigest: new Uint8Array(32).fill(7),
    }),
    "same",
  );
});

test("calls client: pins on first sight, raises a change once, and holds a verified contact", async () => {
  const alice = await deviceFor("u_alice", "d_alice");
  const bob = await deviceFor("u_bob", "d_bob");
  const { client, store } = await clientWith("u_alice", alice);
  const mine = await boundConnection("c1", "l_alice", alice);
  const bobIn = await boundConnection("c1", "l_bob", bob);
  const context = {
    channelId: "c1",
    leaseId: "l_alice",
    oneToOnePeer: "u_bob",
    closed: false,
  };
  const [first] = await client.callPeers([mine, bobIn], context);
  assert.equal(first.leaseId, "l_bob", "your own connection is skipped");
  assert.equal(first.state, "not-verified");
  assert.equal(first.pin, "first");
  assert.equal((await client.trusted()).u_bob, bob.identity.publicKey);
  // Verified, through the same calls private conversations use.
  const code = await client.safetyCodeWith("u_bob");
  await client.markVerified("u_bob", code!);
  assert.equal((await client.callPeers([bobIn], context))[0].state, "verified");

  // The server claims Bob under another identity key: held, alert raised.
  const fake = await deviceFor("u_bob", "d_fake");
  const fakeIn = await boundConnection("c1", "l_bob_2", fake);
  const [held] = await client.callPeers([fakeIn], context);
  assert.equal(held.state, "held");
  assert.equal(held.share, false);
  const changes = await client.keyChanges();
  assert.equal(changes.u_bob.wasVerified, true);
  assert.equal((await client.verified()).u_bob, undefined);
  assert.equal(held.keyChangeAt, changes.u_bob.at);
  // Seen again: still held, and the alert is not raised a second time.
  const again = await client.callPeers([fakeIn], context);
  assert.equal(again[0].state, "held");
  assert.equal((await client.keyChanges()).u_bob.at, changes.u_bob.at);
  // Dismissed: shared again, marked Not verified.
  await client.acknowledgeKeyChange("u_bob", changes.u_bob.at);
  assert.equal((await client.callPeers([fakeIn], context))[0].state, "not-verified");
  // A third account in this one-to-one call.
  const carol = await deviceFor("u_carol", "d_carol");
  const [third] = await client.callPeers(
    [await boundConnection("c1", "l_carol", carol)],
    context,
  );
  assert.equal(third.state, "refused");
  assert.equal(third.refusal, "not-in-conversation");
  assert.equal((await store.get<Record<string, string>>("trusted"))!.u_carol, undefined);
});

test("calls client: your own account on a device that isn't linked gets no key from a linked device", async () => {
  const alice = await deviceFor("u_alice", "d_alice");
  const keys = await makeConnectionKeys();
  const unlinked = { leaseId: "l_a2", userId: "u_alice", publicKey: keys.publicKey, v: 3 };
  const older = { leaseId: "l_a3", userId: "u_alice", publicKey: keys.publicKey };
  const context = { channelId: "g1", leaseId: "l_alice", oneToOnePeer: null, closed: false };
  // A linked device: the server could claim either of these at will.
  const linked = await clientWith("u_alice", alice);
  const refused = await linked.client.callPeers([unlinked, older], context);
  assert.deepEqual(
    refused.map((p) => [p.state, p.share, p.refusal ?? null]),
    [
      ["refused", false, "own-unlinked"],
      ["refused", false, "own-unlinked"],
    ],
  );
  // Its own other linked device is still let in.
  const [other] = await linked.client.callPeers(
    [await boundConnection("g1", "l_a4", alice)],
    context,
  );
  assert.equal(other.state, "you-linked");
  // A device that isn't linked either cannot tell its own devices apart.
  const plain = await clientWith("u_alice");
  const shared = await plain.client.callPeers([unlinked, older], context);
  assert.deepEqual(
    shared.map((p) => [p.state, p.share]),
    [
      ["you-unlinked", true],
      ["you-unlinked", true],
    ],
  );
});

test("calls client: two identity keys for one account at once never flip the pin", async () => {
  const alice = await deviceFor("u_alice", "d_alice");
  const bob = await deviceFor("u_bob", "d_bob");
  const fake = await deviceFor("u_bob", "d_fake");
  const { client } = await clientWith("u_alice", alice);
  const context = {
    channelId: "g1",
    leaseId: "l_alice",
    oneToOnePeer: null,
    closed: false,
  };
  const bobIn = await boundConnection("g1", "l_bob", bob);
  await client.callPeers([bobIn], context);
  const both = await client.callPeers(
    [bobIn, await boundConnection("g1", "l_fake", fake)],
    context,
  );
  assert.deepEqual(
    both.map((p) => [p.state, p.refusal ?? null]),
    [
      ["not-verified", null],
      ["refused", "two-identities"],
    ],
  );
  assert.equal((await client.trusted()).u_bob, bob.identity.publicKey);
  assert.deepEqual(await client.keyChanges(), {});
});

test("calls client: without an identity nothing is pinned and nobody is Verified", async () => {
  const bob = await deviceFor("u_bob", "d_bob");
  const { client, store } = await clientWith("u_alice");
  const [peer] = await client.callPeers(
    [await boundConnection("g1", "l_bob", bob)],
    { channelId: "g1", leaseId: "l_alice", oneToOnePeer: null, closed: false },
  );
  assert.equal(peer.state, "not-verified");
  assert.equal(await store.get("trusted"), undefined);
  // An unbound connection of your own account, and an older app.
  const keys = await makeConnectionKeys();
  const [own, older] = await client.callPeers(
    [
      { leaseId: "l_a2", userId: "u_alice", publicKey: keys.publicKey, v: 3 },
      { leaseId: "l_old", userId: "u_bob", publicKey: keys.publicKey },
    ],
    { channelId: "g1", leaseId: "l_alice", oneToOnePeer: null, closed: true },
  );
  assert.equal(own.state, "you-unlinked");
  assert.equal(older.state, "refused");
  assert.equal(older.refusal, "update-required");
});

test("calls: info, transcript and view bodies refuse bad sizes", () => {
  assert.throws(() =>
    callWrapInfo({
      channelId: "c",
      epoch: "e",
      keyIndex: 16,
      senderHash: new Uint8Array(32),
      recipientHash: new Uint8Array(32),
    }),
  );
  assert.throws(() =>
    callWrapInfo({
      channelId: "c",
      epoch: "e",
      keyIndex: 0,
      senderHash: new Uint8Array(31),
      recipientHash: new Uint8Array(32),
    }),
  );
  assert.throws(() =>
    callCodeTranscript({
      channelId: "c",
      epoch: "e",
      keyIndex: 0,
      hashes: [new Uint8Array(33)],
    }),
  );
  assert.throws(() =>
    callViewBody({
      channelId: "c",
      leaseId: "l",
      epoch: "e",
      keyIndex: 0,
      transcriptDigest: new Uint8Array(31),
    }),
  );
  // The labels are ASCII then one zero byte.
  const info = callWrapInfo({
    channelId: "c",
    epoch: "e",
    keyIndex: 0,
    senderHash: new Uint8Array(32),
    recipientHash: new Uint8Array(32),
  });
  assert.deepEqual(
    [...info.subarray(0, 18)],
    [...te.encode("hubs-call-wrap-v3"), 0],
  );
});


