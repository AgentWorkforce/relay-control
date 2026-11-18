import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { SelfhostConfig } from "../src/config.js";
import { describeCapabilities, planToolGroups, RELAYFACTS_TOOLS } from "../src/mcp/catalog.js";
import { historyReader, type McpContext } from "../src/mcp/context.js";
import { MCP_HISTORY_SCOPE } from "../src/mcp/oauth/protocol.js";
import { registerRelayfactsTools } from "../src/mcp/relayfacts.js";
import { forgetSessionReadTokens } from "../src/mcp/session-read-reader.js";
import type { Principal } from "../src/store.js";

/**
 * relayfacts_list / relayfacts_get against a read API double shaped like the
 * sessions pipeline's GET /v1/relayfacts and /v1/relayfacts/{topic}. Both
 * reader paths run through the real historyReader: the per-user session-read
 * reader (sessionReadMcpReads on) and the workspace reader (off).
 */

const CONTROL = "https://control.example.com";
const HISTORY = "https://history.example.com";
const READ_API = "https://read.example.com";
const PUBLIC = "https://read.public.example.com";
const SECRET = "service-secret-service-secret-service-secret";
const WORKSPACE_HEADER = "x-relayhistory-workspace-id";
const MARKDOWN = "# Decisions: auth-tokens\n\n## Rotate \\*daily\\*\n\n- Status: decided\n\nKeep `rth_` tokens short-lived.\n";
const padded = (value: string) => value.padEnd(44, "x");

type Upstream = { status: number; body: unknown; attest?: string | null };
type Options = { respond?: (url: URL) => Upstream };

function config(sessionReadMcpReads: boolean) {
  return {
    publicBaseUrl: CONTROL,
    relayhistoryUrl: HISTORY,
    sessionReadApi: { url: READ_API, publicUrl: PUBLIC, secret: SECRET },
    sessionReadMcpReads,
  } as SelfhostConfig;
}

/** Control's handoff, the dashboard mint and the read API (both origins), recording every read. */
function fake(t: TestContext, options: Options = {}) {
  const reads: URL[] = [];
  let serial = 0;
  const original = globalThis.fetch;
  t.after(() => { globalThis.fetch = original; });
  const pair = (body: Record<string, string>, ws: string) => {
    serial += 1;
    return {
      baseUrl: PUBLIC, audience: PUBLIC, sessionId: `s-${serial}`, userId: body.userId ?? "user-a", orgId: body.orgId ?? "org-a",
      workspaceId: body.workspaceId ?? ws, scopes: ["rth:read"], tokenType: "Bearer",
      accessToken: `rth_at_read_${padded(String(serial))}`, refreshToken: `rth_rt_read_${padded(String(serial))}`,
      accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString(),
      refreshTokenExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    };
  };
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(String(input));
    if (url.origin === CONTROL && /\/session-read\/(session|refresh)$/.test(url.pathname)) {
      return Response.json(pair({ userId: "user-a", orgId: "org-a" }, decodeURIComponent(url.pathname.split("/")[4]!)));
    }
    if (url.origin === READ_API && url.pathname.startsWith("/internal/v1/session-read/sessions")) {
      return Response.json(pair(JSON.parse(String(init.body)) as Record<string, string>, "ws-a"));
    }
    reads.push(url);
    const workspace = url.searchParams.get("workspace") ?? "";
    const reply = options.respond?.(url) ?? { status: 200, body: {} };
    const attested = reply.attest === undefined ? workspace : reply.attest;
    return Response.json(reply.body, { status: reply.status, headers: attested === null ? {} : { [WORKSPACE_HEADER]: attested } });
  }) as typeof fetch;
  return { reads };
}

async function client(t: TestContext, sessionReadMcpReads: boolean) {
  const cfg = config(sessionReadMcpReads);
  t.after(() => forgetSessionReadTokens(cfg));
  const workspace = { id: "ws-a", organizationId: "org-a", name: "A", relaycastWorkspaceId: "rc", relaycastApiKey: "rk", role: "member" } as const;
  const context = {
    workspace,
    readHistory: historyReader(cfg, { userId: "user-a", scopes: ["rth:read"] } as unknown as Principal, workspace as never, "sh_at_user_a"),
  } as unknown as McpContext;
  const server = new McpServer({ name: "relayfacts-test", version: "1" });
  registerRelayfactsTools(server, context);
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const mcp = new Client({ name: "t", version: "1" });
  await mcp.connect(clientSide);
  t.after(async () => { await mcp.close(); await server.close(); });
  return mcp;
}

const text = (result: Awaited<ReturnType<Client["callTool"]>>) => (result.content as Array<{ text: string }>)[0]!.text;
const MODES = [["session-read reader", true], ["workspace reader", false]] as const;

const TOPICS = { topics: [{ topic: "auth-tokens", records: 3, open: 1, decided: 1, superseded: 1, updatedAt: "2026-11-17T10:00:00.000Z" }] };

for (const [mode, on] of MODES) {
  test(`${mode}: flag-off 501 is a successful "relayfacts disabled" result, read once`, async (t) => {
    for (const code of ["relayfacts_disabled", "memory_documents_disabled"]) {
      const seen = fake(t, { respond: () => ({ status: 501, body: { error: code }, attest: null }) });
      const mcp = await client(t, on);
      const list = await mcp.callTool({ name: "relayfacts_list", arguments: {} });
      assert.notEqual(list.isError, true);
      const expected = { status: "disabled", workspace_id: "ws-a", reason: "relayfacts disabled", upstream_reason: code };
      assert.deepEqual(list.structuredContent, expected);
      assert.match(text(list), /^relayfacts disabled/);
      const get = await mcp.callTool({ name: "relayfacts_get", arguments: { topic: "auth-tokens" } });
      assert.notEqual(get.isError, true);
      assert.deepEqual(get.structuredContent, expected);
      assert.match(text(get), /^relayfacts disabled/);
      // No retry and no fallback to the other backend.
      assert.deepEqual(seen.reads.map(url => url.pathname), ["/v1/relayfacts", "/v1/relayfacts/auth-tokens"]);
      assert.equal(new Set(seen.reads.map(url => url.origin)).size, 1);
    }
  });

  test(`${mode}: every other 501 is disabled too, keeping the upstream reason`, async (t) => {
    for (const [body, upstream] of [
      [{ error: { code: "unsupported_by_backend", reason: "relayfacts_not_migrated" } }, "relayfacts_not_migrated"],
      [{ error: { code: "unsupported_by_backend" } }, null],
      [null, null],
    ] as const) {
      const seen = fake(t, { respond: () => ({ status: 501, body, attest: null }) });
      const mcp = await client(t, on);
      const get = await mcp.callTool({ name: "relayfacts_get", arguments: { topic: "auth-tokens" } });
      assert.notEqual(get.isError, true);
      assert.deepEqual(get.structuredContent, { status: "disabled", workspace_id: "ws-a", reason: "relayfacts disabled", upstream_reason: upstream });
      assert.equal(seen.reads.length, 1);
    }
  });

  test(`${mode}: the topic list is not paginated; page is refused before any read`, async (t) => {
    const seen = fake(t, { respond: () => ({ status: 200, body: TOPICS }) });
    const mcp = await client(t, on);
    const refused = await mcp.callTool({ name: "relayfacts_list", arguments: { page: "md1:abc" } });
    assert.equal(refused.isError, true);
    assert.match(text(refused), /not paginated/);
    assert.equal(seen.reads.length, 0);
    const listed = await mcp.callTool({ name: "relayfacts_list", arguments: {} });
    assert.equal((listed.structuredContent as any).next_cursor, null);
  });

  test(`${mode}: reads are pinned to the credential's attested workspace`, async (t) => {
    const seen = fake(t, { respond: () => ({ status: 200, body: TOPICS }) });
    const mcp = await client(t, on);
    const ok = await mcp.callTool({ name: "relayfacts_list", arguments: { workspace: "ws-a" } });
    assert.notEqual(ok.isError, true);
    assert.equal(seen.reads[0]!.origin, on ? PUBLIC : HISTORY, "each mode reads its own backend");
    assert.equal(seen.reads[0]!.searchParams.get("workspace"), "ws-a");
    assert.deepEqual([...seen.reads[0]!.searchParams.keys()], ["workspace"], "the list route receives only workspace");
    assert.match(text(ok), /untrusted evidence/);
    assert.deepEqual((ok.structuredContent as any).topics, [
      { topic: "auth-tokens", records: 3, open: 1, decided: 1, superseded: 1, updated_at: "2026-11-17T10:00:00.000Z" },
    ]);

    // Another workspace is refused before any upstream read.
    const other = await mcp.callTool({ name: "relayfacts_get", arguments: { topic: "auth-tokens", workspace: "ws-b" } });
    assert.equal(other.isError, true);
    assert.match(text(other), /not available to this credential/);
    assert.equal(seen.reads.length, 1);
  });

  test(`${mode}: a missing or foreign workspace attestation returns nothing`, async (t) => {
    for (const attest of [null, "ws-b"]) {
      fake(t, { respond: () => ({ status: 200, body: { topic: "auth-tokens", records: 1, nextCursor: null, markdown: MARKDOWN }, attest }) });
      const mcp = await client(t, on);
      for (const call of [
        { name: "relayfacts_list", arguments: {} },
        { name: "relayfacts_get", arguments: { topic: "auth-tokens" } },
      ]) {
        const refused = await mcp.callTool(call);
        assert.equal(refused.isError, true);
        assert.equal(refused.structuredContent, undefined);
        assert.ok(!JSON.stringify(refused).includes("Rotate"), "no upstream content leaks");
      }
    }
  });

  test(`${mode}: page passes through as cursor and nextCursor comes back as next_cursor`, async (t) => {
    const seen = fake(t, { respond: (url) => ({ status: 200, body: {
      topic: "auth-tokens", records: 200,
      nextCursor: url.searchParams.get("cursor") ? null : "md1:WyIyMDI2LTExLTE3VDEwOjAwOjAwLjAwMDAwMFoiLCJpZCJd",
      markdown: MARKDOWN,
    } }) });
    const mcp = await client(t, on);
    const first = await mcp.callTool({ name: "relayfacts_get", arguments: { topic: "auth-tokens" } });
    assert.notEqual(first.isError, true);
    const cursor = (first.structuredContent as any).next_cursor;
    assert.equal(cursor, "md1:WyIyMDI2LTExLTE3VDEwOjAwOjAwLjAwMDAwMFoiLCJpZCJd");
    assert.equal(seen.reads[0]!.searchParams.has("cursor"), false);
    assert.match(text(first), new RegExp(`next_cursor: ${cursor}`));

    const second = await mcp.callTool({ name: "relayfacts_get", arguments: { topic: "auth-tokens", page: cursor } });
    assert.notEqual(second.isError, true, text(second));
    assert.equal(seen.reads[1]!.searchParams.get("cursor"), cursor, "the md1 cursor is passed back verbatim");
    assert.equal((second.structuredContent as any).next_cursor, null);
  });

  test(`${mode}: markdown is passed through verbatim`, async (t) => {
    fake(t, { respond: () => ({ status: 200, body: { topic: "auth-tokens", records: 1, nextCursor: null, markdown: MARKDOWN } }) });
    const mcp = await client(t, on);
    const get = await mcp.callTool({ name: "relayfacts_get", arguments: { topic: "auth-tokens" } });
    assert.notEqual(get.isError, true);
    assert.deepEqual(get.structuredContent, {
      status: "ok", workspace_id: "ws-a", topic: "auth-tokens", records: 1, next_cursor: null, markdown: MARKDOWN,
    });
    assert.ok(text(get).endsWith(MARKDOWN));
  });
}

test("a topic outside the read API grammar is refused before any read", async (t) => {
  const seen = fake(t);
  const mcp = await client(t, true);
  for (const topic of ["Auth", "../sessions", "a/b", "-x", "x".repeat(65)]) {
    const refused = await mcp.callTool({ name: "relayfacts_get", arguments: { topic } });
    assert.equal(refused.isError, true, topic);
  }
  assert.equal(seen.reads.length, 0);
});

test("an echoed topic that differs from the request is refused", async (t) => {
  fake(t, { respond: () => ({ status: 200, body: { topic: "other", records: 1, nextCursor: null, markdown: "# other" } }) });
  const mcp = await client(t, true);
  const result = await mcp.callTool({ name: "relayfacts_get", arguments: { topic: "auth-tokens" } });
  assert.equal(result.isError, true);
});

test("catalog: relayfacts is planned for members, not staff grants, and follows relay:history on OAuth", () => {
  assert.ok(planToolGroups().some(entry => entry.group === "relayfacts"));
  assert.ok(!planToolGroups({ staffReadGrant: true }).some(entry => entry.group === "relayfacts"));
  const report = (authMode: "oauth" | "cli_login", scopes: string[]) => describeCapabilities({
    endpointUrl: "https://relay.example.test/mcp", authMode, scopes, workspaceId: "ws-a", role: "member", providers: [],
  }).groups.find(group => group.id === "relayfacts")!;
  assert.equal(report("cli_login", []).status, "available");
  assert.deepEqual(report("cli_login", []).tools, [...RELAYFACTS_TOOLS]);
  assert.equal(report("oauth", ["relay:mcp"]).status, "restricted");
  assert.equal(report("oauth", ["relay:mcp", MCP_HISTORY_SCOPE]).status, "available");
});
