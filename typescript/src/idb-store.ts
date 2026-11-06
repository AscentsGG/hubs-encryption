/**
 * The device store for private conversations in a browser: one IndexedDB
 * database per account, on this device only.
 *
 * Every value is sealed with AES-256-GCM under a key that WebCrypto made
 * non-extractable. IndexedDB keeps that key as a CryptoKey object, so no
 * script can read its bytes, and a sealed value copied out of the database
 * opens nothing on its own. What this does and does not stop:
 *
 * - It stops reading keys and messages with tools that dump or export
 *   IndexedDB values (developer tools, backup and sync tools, extensions
 *   that cannot run script on this page), and casual reading of the files
 *   on disk.
 * - Safari wraps stored CryptoKeys with a key from the system keychain, so
 *   a copy of the browser's files does not open elsewhere. Chrome, Edge,
 *   Firefox and Electron keep the key material in the same profile files
 *   as the values, so someone who copies the whole profile and decodes the
 *   browser's storage format can still recover it.
 * - Script running on this page can use the key while it runs, exactly as
 *   this code does. Keeping other script off the page (a strict content
 *   security policy) is what protects against that.
 */
import type { ConversationLocks, DeviceStore } from "./client.js";

const STORE = "values";
const KEYS = "keys";
/** Version 2 added the key store; values from version 1 are plain and get sealed in place. */
const VERSION = 2;
/** Labels the sealed format, so a later format can tell the two apart. */
const SEAL_LABEL = "hubs private dms store v1";

/** Each account's database name starts with this. */
const DATABASE_PREFIX = "hubs-private-dms-";

/** A plain key-value backend the sealed store writes to (IndexedDB in a browser). */
export interface StoreBackend {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
}

type Sealed = { v: 1; iv: Uint8Array; data: ArrayBuffer };
const isSealed = (value: unknown): value is Sealed =>
  !!value &&
  typeof value === "object" &&
  (value as Sealed).v === 1 &&
  ArrayBuffer.isView((value as Sealed).iv) &&
  (value as Sealed).data instanceof ArrayBuffer;

const UNREADABLE = "This device's private conversation data could not be read.";

/** A new store key: AES-256-GCM, usable here but never exportable. */
export const newStoreKey = () =>
  crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]) as Promise<CryptoKey>;

/** One at a time per name inside this page, where Web Locks are missing. */
function pageLocks(): ConversationLocks {
  const tails = new Map<string, Promise<unknown>>();
  return {
    request<T>(name: string, work: () => Promise<T>) {
      const result = (tails.get(name) ?? Promise.resolve()).then(work, work);
      const tail = result.catch(() => undefined);
      tails.set(name, tail);
      void tail.then(() => {
        if (tails.get(name) === tail) tails.delete(name);
      });
      return result;
    },
  };
}

/**
 * A DeviceStore that seals every value with `key` before it reaches the
 * backend. Values must be JSON. The additional data names the format, the
 * store and the value's key, so a sealed value moved to another key or
 * another account's store does not open. Every write to one key runs under
 * one lock (Web Locks across tabs, or this page's queue), which keeps
 * `update` a single read and write even though sealing is asynchronous.
 * Values written before sealing are read as they are until `migrate` has
 * sealed them in place. After that (or with `sealed` set, for a store migrated
 * earlier) a value that is not sealed is refused, so nothing can replace a
 * value without the store key.
 */
export function sealedStore(
  backend: StoreBackend,
  key: CryptoKey,
  options: {
    name: string;
    locks?: ConversationLocks | null;
    sealed?: boolean;
  },
): DeviceStore & { migrate(): Promise<number> } {
  const locks =
    (options.locks === undefined
      ? (globalThis.navigator as { locks?: ConversationLocks } | undefined)
          ?.locks
      : options.locks) ?? pageLocks();
  let sealedOnly = options.sealed === true;
  const te = new TextEncoder();
  const aad = (name: string) =>
    te.encode(`${SEAL_LABEL}\0${options.name}\0${name}`);
  const seal = async (name: string, value: unknown): Promise<Sealed> => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aad(name) },
      key,
      te.encode(JSON.stringify(value)),
    );
    return { v: 1, iv, data };
  };
  const open = async <T>(name: string, stored: unknown) => {
    if (stored === undefined) return undefined as T;
    if (!isSealed(stored)) {
      if (sealedOnly) throw new Error(UNREADABLE);
      return stored as T;
    }
    let plain: ArrayBuffer;
    try {
      plain = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: stored.iv as Uint8Array<ArrayBuffer>,
          additionalData: aad(name),
        },
        key,
        stored.data,
      );
    } catch {
      throw new Error(UNREADABLE);
    }
    return JSON.parse(new TextDecoder().decode(plain)) as T;
  };
  const exclusive = <T>(name: string, work: () => Promise<T>) =>
    locks.request(`hubs-private-dms-store:${options.name}:${name}`, work);
  return {
    get: async <T>(name: string) => open<T>(name, await backend.get(name)),
    set: (name, value) =>
      exclusive(name, async () => backend.put(name, await seal(name, value))),
    delete: (name) => exclusive(name, () => backend.delete(name)),
    keys: (prefix) => backend.keys(prefix),
    update: <T>(
      name: string,
      change: (current: T | undefined) => T | undefined,
    ) =>
      exclusive(name, async () => {
        const next = change(await open<T>(name, await backend.get(name)));
        if (next !== undefined) await backend.put(name, await seal(name, next));
      }),
    async migrate() {
      let sealed = 0;
      for (const name of await backend.keys("")) {
        await exclusive(name, async () => {
          const stored = await backend.get(name);
          if (stored === undefined || isSealed(stored)) return;
          await backend.put(name, await seal(name, stored));
          sealed++;
        });
      }
      sealedOnly = true;
      return sealed;
    },
  };
}

function openDatabase(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, VERSION);
    let blocked = false;
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      if (!db.objectStoreNames.contains(KEYS)) db.createObjectStore(KEYS);
    };
    // A tab still running the older code holds the old version open, and
    // the upgrade waits for it. Say so instead of waiting without a word.
    request.onblocked = () => {
      blocked = true;
      reject(
        new Error(
          "Hubs is open in another tab with an older version. Reload or close that tab, then try again.",
        ),
      );
    };
    request.onsuccess = () => {
      const db = request.result;
      if (blocked) return db.close();
      // A later version opening elsewhere gets the database straight away.
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onerror = () => reject(request.error);
  });
}

/** This database's store key, made the first time. Two tabs racing keep the first one written. */
async function storeKey(db: IDBDatabase): Promise<CryptoKey> {
  const fresh = await newStoreKey();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(KEYS, "readwrite");
    const keys = transaction.objectStore(KEYS);
    let chosen: CryptoKey = fresh;
    const read = keys.get("store");
    read.onsuccess = () => {
      if (read.result) chosen = read.result as CryptoKey;
      else keys.add(fresh, "store");
    };
    transaction.oncomplete = () => resolve(chosen);
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}

/** Read a value of the key store, or write one when `value` is given. */
function keyStoreValue(
  db: IDBDatabase,
  name: string,
  value?: unknown,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const keys = db
      .transaction(KEYS, value === undefined ? "readonly" : "readwrite")
      .objectStore(KEYS);
    const request =
      value === undefined ? keys.get(name) : keys.put(value, name);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbBackend(database: Promise<IDBDatabase>): StoreBackend {
  const run = async <T>(
    mode: IDBTransactionMode,
    work: (store: IDBObjectStore) => IDBRequest,
  ) => {
    const db = await database;
    return new Promise<T>((resolve, reject) => {
      const request = work(db.transaction(STORE, mode).objectStore(STORE));
      request.onsuccess = () => resolve(request.result as T);
      request.onerror = () => reject(request.error);
    });
  };
  return {
    get: (key) => run("readonly", (s) => s.get(key)),
    put: async (key, value) => {
      await run("readwrite", (s) => s.put(value, key));
    },
    delete: async (key) => {
      await run("readwrite", (s) => s.delete(key));
    },
    keys: async (prefix) =>
      (
        await run<IDBValidKey[]>("readonly", (s) =>
          s.getAllKeys(IDBKeyRange.bound(prefix, `${prefix}￿`)),
        )
      ).map(String),
  };
}

export function indexedDbStore(userId: string): DeviceStore {
  const database = openDatabase(`${DATABASE_PREFIX}${userId}`);
  const ready = database.then(async (db) => {
    const sealed = !!(await keyStoreValue(db, "sealed"));
    const store = sealedStore(idbBackend(database), await storeKey(db), {
      name: userId,
      sealed,
    });
    // Seal what an earlier version stored in the clear, once: no tab of an
    // earlier version can open this database again, so nothing new arrives
    // in the clear. Reads handle both until this is done, so nothing waits.
    if (!sealed)
      void (async () => {
        await store.migrate();
        await keyStoreValue(db, "sealed", true);
      })().catch(() => undefined);
    return store;
  });
  return {
    get: async <T>(key: string) => (await ready).get<T>(key),
    set: async (key, value) => (await ready).set(key, value),
    delete: async (key) => (await ready).delete(key),
    keys: async (prefix) => (await ready).keys(prefix),
    update: async <T>(
      key: string,
      change: (current: T | undefined) => T | undefined,
    ) => (await ready).update<T>(key, change),
  };
}

/** The accounts with a store in this browser, whether or not it holds a device yet. */
export async function deviceStoreAccounts(): Promise<string[]> {
  if (typeof indexedDB === "undefined" || !indexedDB.databases) return [];
  return (await indexedDB.databases()).flatMap(({ name }) =>
    name?.startsWith(DATABASE_PREFIX)
      ? [name.slice(DATABASE_PREFIX.length)]
      : [],
  );
}

/**
 * Deletes an account's whole store from this browser: its keys, messages and
 * store key. Tabs that have it open close it when this asks (openDatabase).
 * False when a tab running older code still holds it, or the browser refused.
 */
export function deleteDeviceStore(userId: string): Promise<boolean> {
  return new Promise((resolve) => {
    if (typeof indexedDB === "undefined") return resolve(true);
    const request = indexedDB.deleteDatabase(`${DATABASE_PREFIX}${userId}`);
    request.onsuccess = () => resolve(true);
    request.onerror = () => resolve(false);
    request.onblocked = () => resolve(false);
  });
}

/** True when this browser can hold private conversation keys (WebCrypto Ed25519 and X25519). */
export async function deviceSupported(): Promise<boolean> {
  try {
    if (typeof indexedDB === "undefined" || !globalThis.crypto?.subtle)
      return false;
    await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]);
    await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    return true;
  } catch {
    return false;
  }
}

/**
 * The passkey backup secret: the WebAuthn PRF output of one of this
 * person's passkeys. Null where the passkey or browser has no PRF.
 */
export async function passkeySecret(): Promise<{
  secret: Uint8Array;
  credentialId: string;
} | null> {
  if (typeof PublicKeyCredential === "undefined") return null;
  const salt = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode("hubs private dms backup prf v1"),
    ),
  );
  const credential = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: "required",
      extensions: { prf: { eval: { first: salt } } },
    } as PublicKeyCredentialRequestOptions,
  })) as PublicKeyCredential | null;
  const results = (
    credential?.getClientExtensionResults() as {
      prf?: { results?: { first?: ArrayBuffer } };
    }
  )?.prf?.results?.first;
  if (!credential || !results) return null;
  return { secret: new Uint8Array(results), credentialId: credential.id };
}
