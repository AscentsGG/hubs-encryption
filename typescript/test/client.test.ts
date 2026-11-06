import test from "node:test";
import assert from "node:assert/strict";
import {
  type PrivateDmApi,
  PrivateDmClient,
  groupWriteProblem,
  memoryStore,
} from "../src/index.js";

test("the write guard refuses an older epoch or generation", () => {
  const problem = groupWriteProblem;
  // Same epoch: only the writer that started from the stored generation.
  assert.equal(
    problem({ epoch: 3, generation: 7 }, { epoch: 3, baseGeneration: 7 }),
    null,
  );
  assert.match(
    problem({ epoch: 3, generation: 7 }, { epoch: 3, baseGeneration: 6 })!,
    /moved on/,
  );
  assert.match(
    problem({ epoch: 3, generation: 7 }, { epoch: 3, baseGeneration: 8 })!,
    /moved on/,
  );
  // An older epoch never; a newer epoch always (all of its keys are new).
  assert.match(
    problem({ epoch: 3, generation: 7 }, { epoch: 2, baseGeneration: 7 })!,
    /older/,
  );
  assert.equal(
    problem({ epoch: 3, generation: 7 }, { epoch: 4, baseGeneration: 2 }),
    null,
  );
  // Clearing the group follows the generation, and keeps the epoch as a floor.
  assert.equal(
    problem({ epoch: 3, generation: 7 }, { epoch: null, baseGeneration: 7 }),
    null,
  );
  assert.match(
    problem({ epoch: 3, generation: 7 }, { epoch: null, baseGeneration: 5 })!,
    /moved on/,
  );
  // A conversation stored without a generation, or not stored yet.
  assert.equal(problem({}, { epoch: 0, baseGeneration: 0 }), null);
  assert.equal(problem(undefined, { epoch: 1, baseGeneration: 0 }), null);
});

test("the send check sees the trimmed text and refuses before anything is encrypted or sent", async () => {
  const calls: string[] = [];
  const api: PrivateDmApi = async (method, path) => {
    calls.push(`${method} ${path}`);
    throw new Error("No server in this test.");
  };
  const checked: string[] = [];
  const client = new PrivateDmClient(api, memoryStore(), "u_a", Date.now, {
    locks: null,
    sendCheck: (text) => {
      checked.push(text);
      return text.includes("password")
        ? "Keep passwords out of messages."
        : null;
    },
  });
  const conversation = { id: "conversation-1", timerSeconds: 3600 };
  await assert.rejects(
    client.send(conversation, "  my password is hunter2  "),
    /Keep passwords out of messages/,
  );
  // Text the check accepts goes on, and stops at the missing device keys.
  await assert.rejects(
    client.send(conversation, "See you at six."),
    /Set up private conversations on this device first/,
  );
  assert.deepEqual(checked, ["my password is hunter2", "See you at six."]);
  assert.deepEqual(calls, []);
});
