import assert from "node:assert/strict";
import { test } from "node:test";
import { admissionConnectorKind, connectorKind, hostOf, type ConnectorKind } from "../src/mcp/oauth/connector-kind.js";

const classifications: ReadonlyArray<readonly [string, ConnectorKind]> = [
  // Cursor cloud agents, including a Grok Bot running as one.
  ["https://cursor.com/agents/fake/callback", "cursor-cloud"],
  ["https://www.cursor.com/agents/fake/callback", "cursor-cloud"],
  ["https://cursor.com/agents", "mcp"],
  ["https://cursor.com/other/fake/callback", "mcp"],
  ["cursor://agents/fake/callback", "mcp"],
  ["https://evil-cursor.com/agents/fake/callback", "mcp"],
  ["https://cursor.com.attacker.test/agents/fake/callback", "mcp"],
  ["https://x.ai/callback", "grok-bot"],
  ["https://routine.x.ai/callback", "grok-bot"],
  ["https://evil-x.ai/callback", "mcp"],
  ["https://x.ai.attacker.test/callback", "mcp"],
  ["https://chatgpt.com/callback", "chatgpt"],
  ["https://api.openai.com/callback", "chatgpt"],
  ["https://muse.ai/callback", "muse"],
  ["https://agent.meta.ai/callback", "muse"],
  ["http://muse.ai/callback", "mcp"],
  ["https://muse.ai.attacker.test/callback", "mcp"],
  ["not a URL", "mcp"],
];
for (const [uri, expected] of classifications) {
  test(`connector classifies ${uri} as ${expected}`, () => {
    assert.equal(connectorKind({ clientName: null, redirectUris: [uri] }), expected);
  });
}

test("mixed registrations retain Cursor, Grok, then ChatGPT then Muse precedence in either URI order", () => {
  const grok = "https://www.cursor.com/agents/fake/callback";
  const chatgpt = "https://chatgpt.com/callback";
  const muse = "https://muse.ai/callback";
  for (const uris of [[grok, chatgpt, muse], [muse, chatgpt, grok]]) {
    assert.equal(connectorKind({ clientName: "fake-muse", redirectUris: uris }), "cursor-cloud");
  }
  assert.equal(connectorKind({ clientName: null, redirectUris: ["https://x.ai/callback", "https://chatgpt.com/callback"] }), "grok-bot");
  for (const uris of [[chatgpt, muse], [muse, chatgpt]]) {
    assert.equal(connectorKind({ clientName: "fake-grok", redirectUris: uris }), "chatgpt");
  }
  assert.equal(connectorKind({ clientName: "Grok Bot ChatGPT Muse", redirectUris: ["https://other.example.test/callback"] }), "mcp");
});

test("admission kind refuses registrations that name two different providers", () => {
  const grok = "https://www.cursor.com/agents/fake/callback";
  const chatgpt = "https://chatgpt.com/callback";
  const muse = "https://muse.ai/callback";
  for (const uris of [[grok, chatgpt], [chatgpt, grok], [chatgpt, muse], [grok, muse], [grok, chatgpt, muse]]) {
    assert.equal(admissionConnectorKind({ clientName: "fake-grok", redirectUris: uris }), "mcp");
  }
  assert.equal(admissionConnectorKind({ clientName: "Grok Bot", redirectUris: ["https://other.example.test/callback"] }), "mcp");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [] }), "mcp");
});

test("admission kind from the registration needs every redirect URI to name the same provider", () => {
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: ["https://chatgpt.com/a", "https://api.openai.com/b"] }), "chatgpt");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: ["https://muse.ai/callback"] }), "muse");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: ["https://www.cursor.com/agents/fake/callback"] }), "cursor-cloud");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: ["https://x.ai/callback"] }), "grok-bot");
  // A callback of its own beside a provider's is where such a client would receive its codes.
  for (const provider of ["https://chatgpt.com/callback", "https://muse.ai/callback", "https://www.cursor.com/agents/fake/callback"]) {
    for (const own of ["https://attacker.example.test/callback", "http://localhost:8787/callback", "http://127.0.0.1:8787/callback"]) {
      assert.equal(admissionConnectorKind({ clientName: "ChatGPT", redirectUris: [provider, own] }), "mcp");
      assert.equal(admissionConnectorKind({ clientName: "ChatGPT", redirectUris: [own, provider] }), "mcp");
    }
  }
});

test("admission kind follows the redirect URIs the grant's codes were delivered to", () => {
  const grok = "https://www.cursor.com/agents/fake/callback";
  const chatgpt = "https://chatgpt.com/callback";
  const own = "https://attacker.example.test/callback";
  const local = "http://localhost:8787/callback";
  // A provider that also registers a loopback callback is still that provider when its codes went to its own callback.
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [grok, local] }, [grok]), "cursor-cloud");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [chatgpt, own] }, [chatgpt]), "chatgpt");
  // The same registrations are no provider when a code went anywhere else.
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [grok, local] }, [local]), "mcp");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [chatgpt, own] }, [own]), "mcp");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [chatgpt, own] }, [chatgpt, own]), "mcp");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [grok, chatgpt] }, [grok, chatgpt]), "mcp");
  // The delivery decides even when the registration alone names one provider.
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [chatgpt] }, [own]), "mcp");
});

test("host parsing normalizes hostname and keeps display port/path; malformed URI stays null", () => {
  assert.deepEqual(hostOf("https://WWW.X.AI:8443/fake/callback"), {
    scheme: "https", host: "www.x.ai", displayHost: "www.x.ai:8443", path: "/fake/callback",
  });
  assert.equal(hostOf("https://[bad"), null);
});

test("Grok Bot routines stay available to Cursor cloud agents, the way a Cursor-hosted Grok Bot connects", async () => {
  const { isGrokRoutineKind } = await import("../src/mcp/oauth/connector-kind.js");
  assert.equal(isGrokRoutineKind("grok-bot"), true);
  assert.equal(isGrokRoutineKind("cursor-cloud"), true);
  for (const kind of ["chatgpt", "muse", "mcp"] as const) assert.equal(isGrokRoutineKind(kind), false);
});
