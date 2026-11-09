import assert from "node:assert/strict";
import test from "node:test";
import { RelaycastCallError } from "../src/messaging/relaycast.js";
import { cleanupFailure, cleanupRetryAt, McpCleanupBlocked } from "../src/mcp/oauth/teardown-policy.js";

test("cleanup retry delay grows from 15 seconds and stays bounded through repeated failures", () => {
  const now = new Date("2026-01-01T00:00:00Z");
  const delays = [1, 2, 3, 8, 100].map(attempt => cleanupRetryAt(attempt, now).getTime() - now.getTime());
  assert.deepEqual(delays.slice(0, 3), [15_000, 30_000, 60_000]);
  assert.ok(delays.every(delay => delay >= 15_000 && delay <= 3_600_000));
  assert.ok(delays.every((delay, index) => index === 0 || delay >= delays[index - 1]!));
  assert.equal(now.toISOString(), "2026-01-01T00:00:00.000Z");
});

test("only transient remote failures retry; credential and ownership failures require operator attention", () => {
  for (const status of [0, 408, 409, 429, 500, 503]) {
    assert.deepEqual(cleanupFailure(new RelaycastCallError(status, "fake private upstream body")),
      { retryable: true, reason: "upstream_unavailable" });
  }
  for (const status of [401, 403]) assert.deepEqual(cleanupFailure(new RelaycastCallError(status, "fake private body")),
    { retryable: false, reason: "upstream_auth_refused" });
  assert.deepEqual(cleanupFailure(new RelaycastCallError(400, "fake private body")),
    { retryable: false, reason: "upstream_refused" });
  assert.deepEqual(cleanupFailure(new McpCleanupBlocked("agent_ownership_changed")),
    { retryable: false, reason: "agent_ownership_changed" });
  assert.deepEqual(cleanupFailure(new Error("fake secret")), { retryable: true, reason: "internal_error" });
});
