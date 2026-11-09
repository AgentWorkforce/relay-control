import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { AmpConfig } from "../src/amp/config.js";
import type { HistoryUploader, PushSessionFactory } from "../src/amp/history.js";
import { createAmpModule, type AmpModule } from "../src/amp/module.js";
import { AMP_CLI_VERSION, type AmpOperation } from "../src/amp/provider.js";
import { signWebhook } from "../src/amp/webhook.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { apiClient, BOOTSTRAP, close, listen, PGliteDatabase, type Api } from "./flows-helpers.js";
import { createRelaycastWorld, type RelaycastWorld } from "./support/relaycast-world.js";

export const AMP_KEY = "sgamp_owner_key_abcdefghijklmnop";
export const OTHER_KEY = "sgamp_other_key_abcdefghijklmnop";
export const THREAD = "T-0123456789abcdef";
export const THREAD_2 = "T-fedcba9876543210";
export const INTERNAL_SECRET = "amp-internal-secret-that-is-at-least-32-bytes";
export const SERVICE_TOKEN = "service-token-that-is-at-least-32-bytes";
const TRANSPORT = "https://amp-transport.test/";
const TRANSPORT_TOKEN = "amp-transport-token-that-is-at-least-32-bytes";

type TransportCall = { key: string; operation: AmpOperation };
type Reply = { ok: true; value: unknown } | { ok: false; outcome: "rejected" | "unknown" };

/**
 * A fake persistent Amp process service at AMP_TRANSPORT_ORIGIN. Threads are
 * readable only by the keys listed for them; inject appends a user message
 * (the prompt) to the thread, so an export probe can find the marker.
 */
export function createAmpTransport() {
  const calls: TransportCall[] = [];
  const threads = new Map<string, { keys: Set<string>; messages: Array<Record<string, unknown>> }>();
  /** Per-kind overrides; a function runs before the default (and may return a reply). */
  const hooks: Partial<Record<AmpOperation["kind"], (call: TransportCall) => Promise<Reply | void> | Reply | void>> = {};
  let sequence = 0;
  const addThread = (id: string, ...keys: string[]) => threads.set(id, { keys: new Set(keys), messages: [] });
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init?.headers);
    assert.equal(url.href, "https://amp-transport.test/v1/internal/amp/operation");
    assert.equal(headers.get("authorization"), `Bearer ${TRANSPORT_TOKEN}`);
    const body = JSON.parse(String(init?.body)) as { v: number; cliVersion: string; key: string; operation: AmpOperation };
    assert.equal(body.v, 1);
    assert.equal(body.cliVersion, AMP_CLI_VERSION);
    const call = { key: body.key, operation: body.operation };
    calls.push(call);
    const respond = (reply: Reply) => new Response(JSON.stringify({ v: 1, cliVersion: AMP_CLI_VERSION, ...reply }), {
      status: reply.ok ? 200 : 502, headers: { "content-type": "application/json" },
    });
    const hooked = await hooks[call.operation.kind]?.(call);
    if (hooked) return respond(hooked);
    const operation = call.operation;
    if (operation.kind === "discover") {
      return respond({ ok: true, value: [...threads.entries()]
        .filter(([, thread]) => thread.keys.has(call.key)).map(([id]) => ({ id, title: `Thread ${id}` })) });
    }
    const thread = threads.get(operation.threadId);
    if (!thread || !thread.keys.has(call.key)) return respond({ ok: false, outcome: "rejected" });
    if (operation.kind === "export") {
      return respond({ ok: true, value: { id: operation.threadId, createdAt: "2026-11-08T00:00:00.000Z", messages: thread.messages } });
    }
    thread.messages.push({ messageID: `msg-${++sequence}`, role: "user", content: operation.text, createdAt: "2026-11-08T00:00:01.000Z" });
    return respond({ ok: true, value: { accepted: true } });
  }) as typeof fetch;
  return {
    calls, threads, hooks, addThread, fetchImpl,
    injects: () => calls.filter((call) => call.operation.kind === "inject"),
  };
}

export type AmpTransport = ReturnType<typeof createAmpTransport>;

function relaycastFetch(world: RelaycastWorld): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" && init.body ? JSON.parse(init.body) as Record<string, any> : null;
    const handled = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams,
      (headers.get("authorization") ?? "").replace(/^Bearer /, ""), body, headers.get("idempotency-key"));
    const json = (status: number, payload: unknown) => new Response(JSON.stringify(payload), {
      status, headers: { "content-type": "application/json" },
    });
    return handled ? json(handled.status, handled.body) : json(404, { ok: false, error: { code: "not_found" } });
  }) as typeof fetch;
}

export function ampConfig(overrides: Partial<AmpConfig> = {}): AmpConfig {
  return {
    enabled: true,
    transport: { origin: TRANSPORT, token: TRANSPORT_TOKEN },
    internalSecret: INTERNAL_SECRET,
    workerIntervalMs: 600_000,
    leaseMs: 60_000,
    ...overrides,
  };
}

/**
 * The control plane with Amp wired as server.ts wires it, a fake Amp
 * transport, a fake Relaycast, and a controllable clock. `amp: null` builds
 * the app without the Amp module at all.
 */
export async function startAmp(t: TestContext, options: {
  amp?: AmpConfig | null;
  /** History fakes; omitted means production's null push session. */
  pushSession?: PushSessionFactory | null;
  historyUpload?: HistoryUploader;
} = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: "https://control.selfhosted.company",
    relaycastUrl: "http://relaycast.relay.svc.cluster.local",
    relaycastPublicUrl: "https://relaycast.selfhosted.company",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.company",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.company", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    port: 3000,
    host: "127.0.0.1",
    internalServiceToken: SERVICE_TOKEN,
    oauthRedirectUrl: "https://control.selfhosted.company/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.selfhosted.company/",
  };
  const clock = { now: new Date("2026-11-08T12:00:00.000Z") };
  const roster: unknown[] = [];
  const world = createRelaycastWorld(roster);
  const transport = createAmpTransport();
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const messagingFetch = relaycastFetch(world);
  const amp: AmpModule | undefined = options.amp === null ? undefined : createAmpModule({
    amp: options.amp ?? ampConfig(),
    config,
    database,
    relaycastFetch: messagingFetch,
    transportFetch: transport.fetchImpl,
    now: () => clock.now,
    pushSession: options.pushSession ?? null,
    ...(options.historyUpload ? { historyUpload: options.historyUpload } : {}),
  });
  const server = createServer(createApp({ config, store, amp, messagingFetch }));
  const origin = await listen(server);
  t.after(async () => {
    await amp?.stop();
    await close(server);
    await database.close();
  });
  const api = apiClient(origin);
  const tenant = await seed(api);
  return { database, store, config, clock, world, transport, amp, api, origin, ...tenant };
}

async function seed(api: Api) {
  const org = await api("/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const organizationId = org.body.id as string;
  const workspace = async (name: string, key: string) => {
    const created = await api(`/api/v1/organizations/${organizationId}/workspaces`, {
      method: "POST", token: BOOTSTRAP, body: { name, relaycastWorkspaceId: `rc-${name}`, relaycastApiKey: key },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const workspaceId = await workspace("primary", "rk_live_primary");
  const otherWorkspaceId = await workspace("other", "rk_live_other");
  const person = async (email: string, role: "admin" | "member") => {
    const created = await api(`/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST", token: BOOTSTRAP, body: { email, name: email, role },
    });
    assert.equal(created.status, 200);
    return created.body.userId as string;
  };
  const login = async (userId: string, inWorkspace = workspaceId) => {
    const started = await api("/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await api("/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: inWorkspace },
    });
    assert.equal(approved.status, 200);
    const token = await api("/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
    assert.equal(token.status, 200);
    return token.body.access_token as string;
  };
  const ownerId = org.body.owner.id as string;
  const adminId = await person("admin@acme.test", "admin");
  const memberId = await person("member@acme.test", "member");
  return {
    organizationId, workspaceId, otherWorkspaceId, ownerId, adminId, memberId, login,
    ownerToken: await login(ownerId),
    adminToken: await login(adminId),
    memberToken: await login(memberId),
    otherOwnerToken: await login(ownerId, otherWorkspaceId),
  };
}

export type AmpHarness = Awaited<ReturnType<typeof startAmp>>;

export const ampPath = (h: AmpHarness, rest = "") => `/api/v1/workspaces/${h.workspaceId}/amp${rest}`;

/** Connects AMP_KEY as `token`'s person and binds THREAD; returns the binding. */
export async function connectAndBind(h: AmpHarness, token = h.ownerToken, threadId = THREAD) {
  if (!h.transport.threads.has(threadId)) h.transport.addThread(threadId, AMP_KEY);
  const connected = await h.api(ampPath(h, "/connection"), { method: "POST", token, body: { key: AMP_KEY } });
  assert.equal(connected.status, 200, connected.text);
  const bound = await h.api(ampPath(h, "/bindings"), { method: "POST", token, body: { threadId } });
  assert.equal(bound.status, 201, bound.text);
  return bound.body as { binding_id: string; thread_id: string; agent: string };
}

/** The binding's Relaycast subscriptions in the fake Relaycast, oldest first. */
export function subscriptionsFor(h: AmpHarness, bindingId: string) {
  const url = `${h.config.publicBaseUrl}/api/v1/amp/relay-events/${bindingId}`;
  return [...h.world.subscriptions.values()].filter((subscription) => subscription.url === url);
}

/** The whsec_ secret bind minted, as Relaycast received it (it signs events with it). */
export function hookSecret(h: AmpHarness, bindingId: string): string {
  const secrets = new Set(subscriptionsFor(h, bindingId).map((subscription) => subscription.secret));
  assert.equal(secrets.size, 1, "both subscriptions carry the one minted secret");
  return [...secrets][0]!;
}

/** A Relaycast-signed DM event addressed to the bound agent. */
export function dmEvent(agent: string, messageId: string, text = "please review", from = "alice") {
  return JSON.stringify({ type: "dm.received", data: { to: agent, message: { id: messageId, agent_name: from, text } } });
}

export async function postEvent(h: AmpHarness, bindingId: string, body: string, options: {
  secret?: string; timestamp?: number; id?: string;
} = {}) {
  const timestamp = options.timestamp ?? Math.floor(h.clock.now.getTime() / 1000);
  const id = options.id ?? `msg_${Math.random().toString(36).slice(2)}`;
  return h.api(`/api/v1/amp/relay-events/${bindingId}`, {
    method: "POST",
    raw: body,
    headers: {
      "content-type": "application/json",
      "webhook-id": id,
      "webhook-timestamp": String(timestamp),
      "webhook-signature": signWebhook(options.secret ?? hookSecret(h, bindingId), id, timestamp, body),
    },
  });
}

export async function internalJob(h: AmpHarness, body: unknown, token: string | null = INTERNAL_SECRET, path = "/api/v1/internal/amp/job") {
  return h.api(path, { method: "POST", ...(token ? { token } : {}), body });
}

/** The reply bearer and request id from the newest injected prompt. */
export function lastReplyCapability(transport: AmpTransport) {
  const inject = transport.injects().at(-1);
  assert(inject && inject.operation.kind === "inject");
  const text = inject.operation.text;
  const bearer = /Bearer (amp_reply_[A-Za-z0-9_-]{43})/.exec(text)?.[1];
  const data = /--data '([^']+)'/.exec(text)?.[1];
  const url = /curl -fsS '([^']+)'/.exec(text)?.[1];
  assert(bearer && data && url);
  return { bearer, url, request: JSON.parse(data) as { to: string; text: string; message_id: string; request_id: string } };
}
