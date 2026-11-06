import test from "node:test";
import assert from "node:assert/strict";
import { type StoreBackend, newStoreKey, sealedStore } from "../src/index.js";

/** A plain key-value backend in memory, standing in for IndexedDB. */
function memoryBackend(): StoreBackend & { raw: Map<string, unknown> } {
  const raw = new Map<string, unknown>();
  return {
    raw,
    async get(key) {
      return structuredClone(raw.get(key));
    },
    async put(key, value) {
      raw.set(key, structuredClone(value));
    },
    async delete(key) {
      raw.delete(key);
    },
    async keys(prefix) {
      return [...raw.keys()].filter((key) => key.startsWith(prefix));
    },
  };
}
const bytesOf = (value: unknown) =>
  Buffer.from(
    JSON.stringify(value, (_key, v) =>
      v instanceof ArrayBuffer || ArrayBuffer.isView(v)
        ? Buffer.from(v as ArrayBuffer).toString("latin1")
        : v,
    ),
    "latin1",
  );

test("the store seals every value at rest with a key no script can export", async () => {
  const backend = memoryBackend();
  const key = await newStoreKey();
  await assert.rejects(crypto.subtle.exportKey("raw", key));
  const store = sealedStore(backend, key, { name: "u_a", locks: null });
  const secret = { signKey: "the identity signing key", n: 7 };
  await store.set("identity", secret);
  assert.deepEqual(await store.get("identity"), secret);
  const stored = backend.raw.get("identity");
  assert.equal(bytesOf(stored).includes("the identity signing key"), false);
  assert.equal(bytesOf(stored).includes("signKey"), false);
  // Each write uses a fresh nonce: the same value never seals the same way.
  await store.set("identity", secret);
  assert.notDeepEqual(backend.raw.get("identity"), stored);
  assert.deepEqual(await store.keys("ident"), ["identity"]);
  await store.delete("identity");
  assert.equal(await store.get("identity"), undefined);
});

test("updates read and write sealed values, and a refused change writes nothing", async () => {
  const backend = memoryBackend();
  const store = sealedStore(backend, await newStoreKey(), {
    name: "u_a",
    locks: null,
  });
  await store.update<number[]>("list", (current) => [...(current ?? []), 1]);
  await store.update<number[]>("list", (current) => [...(current ?? []), 2]);
  assert.deepEqual(await store.get("list"), [1, 2]);
  const before = backend.raw.get("list");
  await store.update<number[]>("list", () => undefined);
  assert.deepEqual(backend.raw.get("list"), before);
  await assert.rejects(
    store.update<number[]>("list", () => {
      throw new Error("refused");
    }),
    /refused/,
  );
  assert.deepEqual(backend.raw.get("list"), before);
  // Updates to one value run one at a time: none is lost.
  await Promise.all(
    Array.from({ length: 20 }, (_, i) =>
      store.update<number[]>("many", (current) => [...(current ?? []), i]),
    ),
  );
  assert.equal(((await store.get<number[]>("many")) ?? []).length, 20);
});

test("a store written before sealing keeps its values and is sealed in place", async () => {
  const backend = memoryBackend();
  const conversation = { group: "group state", cursor: 3 };
  await backend.put("conversation:c1", conversation);
  await backend.put("messages:c1", [{ id: "m1", body: "Hello there" }]);
  const store = sealedStore(backend, await newStoreKey(), {
    name: "u_a",
    locks: null,
  });
  // Readable before and after the migration.
  assert.deepEqual(await store.get("conversation:c1"), conversation);
  assert.equal(await store.migrate(), 2);
  assert.deepEqual(await store.get("conversation:c1"), conversation);
  assert.deepEqual(await store.get("messages:c1"), [
    { id: "m1", body: "Hello there" },
  ]);
  assert.equal(
    bytesOf(backend.raw.get("messages:c1")).includes("Hello"),
    false,
  );
  assert.equal(await store.migrate(), 0);
});

test("a sealed value opens only under its own name, account and key", async () => {
  const backend = memoryBackend();
  const key = await newStoreKey();
  const store = sealedStore(backend, key, { name: "u_a", locks: null });
  await store.set("trusted", { u_b: "Bob's real key" });
  await store.set("verified", { u_b: "Bob's real key" });
  // Swapping two sealed values does not pass one off as the other.
  backend.raw.set("verified", backend.raw.get("trusted"));
  await assert.rejects(store.get("verified"), /could not be read/);
  // Another account's store, or another key, cannot open it either.
  const other = sealedStore(backend, key, { name: "u_b", locks: null });
  await assert.rejects(other.get("trusted"), /could not be read/);
  const stranger = sealedStore(backend, await newStoreKey(), {
    name: "u_a",
    locks: null,
  });
  await assert.rejects(stranger.get("trusted"), /could not be read/);
});
