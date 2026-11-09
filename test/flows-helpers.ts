import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { PGlite } from "@electric-sql/pglite";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { defaultFlowsConfig, type FlowsConfig } from "../src/flows/config.js";
import { FlowsStore } from "../src/flows/store.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import type { ChiefBackend } from '../src/chief/routes.js';
import type { SelectedFeatures } from "../src/features.js";
import { testFeatures } from "./support/features.js";

export class PGliteDatabase implements Database {
  constructor(readonly client = new PGlite()) {}

  async query<T extends Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
  ): Promise<SqlResult<T>> {
    const result = params.length > 0
      ? await this.client.query<T>(sql, params)
      : await this.client.query<T>(sql);
    return { rows: result.rows };
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    return this.client.transaction(async (transaction) => run({
      query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
        const result = params.length > 0
          ? await transaction.query<R>(sql, params)
          : await transaction.query<R>(sql);
        return { rows: result.rows };
      },
      exec: async (sql: string) => {
        await transaction.exec(sql);
      },
    }));
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  async exec(sql: string): Promise<void> {
    await this.client.exec(sql);
  }
}

export async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

export async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => error ? reject(error) : resolve()));
}

export type Api = (
  path: string,
  options?: { method?: string; token?: string; body?: unknown; raw?: string; headers?: Record<string, string> },
) => Promise<{ status: number; body: any; headers: Headers; text: string }>;

export function apiClient(origin: string): Api {
  return async (path, options = {}) => {
    const response = await fetch(`${origin}${path}`, {
      method: options.method ?? "GET",
      headers: {
        ...(options.token ? { authorization: `Bearer ${options.token}` } : {}),
        ...(options.body !== undefined ? { "content-type": "application/json" } : {}),
        ...options.headers,
      },
      ...(options.body !== undefined
        ? { body: JSON.stringify(options.body) }
        : options.raw !== undefined
          ? { body: options.raw }
          : {}),
    });
    const text = await response.text();
    let body: any = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { raw: text };
    }
    return { status: response.status, body, headers: response.headers, text };
  };
}

export const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";

/** `features` defaults to every optional feature selected. */
export async function startControlPlane(
  flowsOverrides: Partial<FlowsConfig> = {},
  chief?: ChiefBackend,
  configOverrides: Partial<SelfhostConfig> = {},
  features: SelectedFeatures = testFeatures(),
) {
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
    internalServiceToken: null,
    oauthRedirectUrl: `https://control.selfhosted.company/api/v1/integrations/oauth/callback`,
    dashboardUrl: `https://control.selfhosted.company/`,
    ...configOverrides,
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const flows = new FlowsStore(
    database,
    config.encryptionKeyring,
    defaultFlowsConfig({ queuePollMs: 25, queuePingMs: 200, ...flowsOverrides }),
    config.relaycastPublicUrl,
  );
  const server = createServer(createApp({ config, store, flows, chief, features }));
  const origin = await listen(server);
  const api = apiClient(origin);
  return {
    config,
    store,
    database,
    flows,
    origin,
    api,
    async stop() {
      await close(server);
      await database.close();
    },
  };
}

/** Bootstraps the installation org, a workspace, and device-flow user tokens. */
export async function seedTenant(api: Api) {
  const org = await api("/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspace = async (name: string, key: string) => {
    const created = await api(`/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastWorkspaceId: `rc-${name}`, relaycastApiKey: key },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const primary = await workspace("primary", "rk_live_primary");
  const other = await workspace("other", "rk_live_other");
  const member = await api(`/api/v1/organizations/${org.body.id}/memberships`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { email: "member@acme.test", name: "Member", role: "member" },
  });
  assert.equal(member.status, 200);
  const login = async (userId: string, workspaceId: string) => {
    const started = await api("/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await api("/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const token = await api("/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(token.status, 200);
    return token.body.access_token as string;
  };
  return {
    organizationId: org.body.id as string,
    workspaceId: primary,
    otherWorkspaceId: other,
    ownerToken: await login(org.body.owner.id, primary),
    otherOwnerToken: await login(org.body.owner.id, other),
    memberToken: await login(member.body.userId, primary),
  };
}

export type SseEvent = { event: string; data: any };

/** Minimal SSE reader mirroring relay packages/cloud/src/worker.ts parsing. */
export function openQueue(origin: string, workerId: string, workerToken: string) {
  const controller = new AbortController();
  const events: SseEvent[] = [];
  const waiters: Array<() => void> = [];
  let ended = false;
  const ready = fetch(`${origin}/api/v1/workers/${workerId}/queue`, {
    headers: { authorization: `Bearer ${workerToken}` },
    signal: controller.signal,
  }).then(async (response) => {
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /text\/event-stream/);
    const reader = response.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    void (async () => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let index: number;
          while ((index = buffer.indexOf("\n\n")) !== -1) {
            const frame = buffer.slice(0, index);
            buffer = buffer.slice(index + 2);
            let event = "message";
            let data = "";
            for (const line of frame.split("\n")) {
              if (line.startsWith("event:")) event = line.slice(6).trim();
              else if (line.startsWith("data:")) data += line.slice(5).trim();
            }
            events.push({ event, data: data ? JSON.parse(data) : {} });
            waiters.splice(0).forEach((wake) => wake());
          }
        }
      } catch {
        // aborted
      } finally {
        ended = true;
        waiters.splice(0).forEach((wake) => wake());
      }
    })();
  });
  return {
    events,
    ready,
    get ended() {
      return ended;
    },
    async next(event: string, timeoutMs = 5_000): Promise<SseEvent> {
      const deadline = Date.now() + timeoutMs;
      let seen = 0;
      while (Date.now() < deadline) {
        for (; seen < events.length; seen += 1) {
          if (events[seen]!.event === event) return events.splice(seen, 1)[0]!;
        }
        if (ended) break;
        await new Promise<void>((resolve) => {
          waiters.push(resolve);
          setTimeout(resolve, 50);
        });
      }
      throw new Error(`timed out waiting for SSE ${event}; saw ${events.map((e) => e.event).join(",")}`);
    },
    close() {
      controller.abort();
    },
  };
}
