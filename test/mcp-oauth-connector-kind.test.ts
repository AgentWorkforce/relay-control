import assert from "node:assert/strict";
import { test } from "node:test";
import { admissionConnectorKind, connectorKind, hostOf, type ConnectorKind } from "../src/mcp/oauth/connector-kind.js";

const classifications: ReadonlyArray<readonly [string, ConnectorKind]> = [
  ["https://cursor.com/agents/fake/callback", "grok-bot"],
  ["https://www.cursor.com/agents/fake/callback", "grok-bot"],
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

test("mixed registrations retain Grok then ChatGPT then Muse precedence in either URI order", () => {
  const grok = "https://www.cursor.com/agents/fake/callback";
  const chatgpt = "https://chatgpt.com/callback";
  const muse = "https://muse.ai/callback";
  for (const uris of [[grok, chatgpt, muse], [muse, chatgpt, grok]]) {
    assert.equal(connectorKind({ clientName: "fake-muse", redirectUris: uris }), "grok-bot");
  }
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

test("admission kind keeps one provider beside neutral cursor and localhost callbacks", () => {
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: [
    "https://www.cursor.com/agents/fake/callback", "cursor://agents/fake/callback", "http://localhost:8787/callback",
  ] }), "grok-bot");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: ["https://chatgpt.com/a", "https://api.openai.com/b"] }), "chatgpt");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: ["https://muse.ai/callback"] }), "muse");
  assert.equal(admissionConnectorKind({ clientName: null, redirectUris: ["cursor://agents/fake/callback"] }), "mcp");
});

test("host parsing normalizes hostname and keeps display port/path; malformed URI stays null", () => {
  assert.deepEqual(hostOf("https://WWW.X.AI:8443/fake/callback"), {
    scheme: "https", host: "www.x.ai", displayHost: "www.x.ai:8443", path: "/fake/callback",
  });
  assert.equal(hostOf("https://[bad"), null);
});
