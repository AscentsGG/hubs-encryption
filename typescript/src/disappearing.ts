import type { DeviceStore, StoredMessage } from "./client.js";

const isLive = (message: StoredMessage, now: number) =>
  message.expiresAt === null || message.expiresAt > now;

/**
 * Removes every message past its timer from every conversation in a store,
 * with what reporting kept beside it. Reading a conversation removes its own
 * expired lines too, but a conversation nobody opens would otherwise keep them
 * for good. This runs apart from the encryption code, so it is cheap to load.
 */
export async function sweepDisappeared(store: DeviceStore, now: number) {
  let removed = 0;
  for (const key of await store.keys("messages:"))
    await store.update<StoredMessage[]>(key, (list) => {
      const kept = list?.filter((message) => isLive(message, now));
      if (!list || !kept || kept.length === list.length) return undefined;
      removed += list.length - kept.length;
      return kept;
    });
  return removed;
}
