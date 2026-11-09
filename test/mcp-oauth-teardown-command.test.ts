import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { McpCleanupCommandError, parseMcpCleanupCommand } from "../src/mcp/oauth/teardown-command.js";

const organizationId = randomUUID(), workspaceId = randomUUID(), intentId = randomUUID();
const tenant = ["--organization", organizationId, "--workspace", workspaceId];

test("cleanup operator mutations require one explicit tenant and intent plus an audit reason", () => {
  assert.deepEqual(parseMcpCleanupCommand(["retry", ...tenant, "--intent", intentId, "--reason", "restored workspace key"]),
    { action: "retry", organizationId, workspaceId, intentId, reason: "restored workspace key" });
  assert.deepEqual(parseMcpCleanupCommand(["list", ...tenant]), { action: "list", organizationId, workspaceId });
  for (const args of [
    ["abandon", ...tenant],
    ["abandon", ...tenant, "--intent", intentId],
    ["retry", ...tenant, "--intent", intentId, "--reason", " "],
    ["list"],
    ["list", "--organization", organizationId],
    ["list", ...tenant, "--workspace", randomUUID()],
    ["list", ...tenant, "--intent", "all"],
    ["abandon", ...tenant, "--intent", intentId, "--reason", "unsafe\nreason"],
    ["abandon", ...tenant, "--intent", intentId, "--reason", "x".repeat(201)],
    ["abandon", ...tenant, "--intent", intentId, "--reason", "operator decision", "--force"],
  ]) assert.throws(() => parseMcpCleanupCommand(args), McpCleanupCommandError);
});

test("invalid operator arguments are not reflected into diagnostic messages", () => {
  const secret = "fake-secret-that-must-not-be-printed";
  assert.throws(() => parseMcpCleanupCommand(["retry", ...tenant, "--intent", secret]),
    error => error instanceof McpCleanupCommandError && !error.message.includes(secret));
});
