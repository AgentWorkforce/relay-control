/**
 * Local development harness: runs the API against an in-process PGlite
 * database (optionally persisted with DEV_PGLITE_DIR), seeds one
 * organization/workspace, and prints the IDs needed to approve a browser
 * login. Never use this in production; it uses fixed development secrets.
 *
 *   npx tsx scripts/dev-server.ts            # http://127.0.0.1:8787
 *   PORT=9000 DEV_PGLITE_DIR=.dev-db npx tsx scripts/dev-server.ts
 */
import { createServer } from "node:http";
import { PGlite } from "@electric-sql/pglite";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { defaultFlowsConfig } from "../src/flows/config.js";
import { FlowsStore } from "../src/flows/store.js";
import { loadLicense } from "../src/license/load.js";
import { gateCredentialVerifier } from "../src/license/resolver.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { pathToFileURL } from 'node:url';
import type { ChiefBackend } from '../src/chief/routes.js';

class PGliteDatabase implements Database {
  constructor(readonly client: PGlite) {}
  async query<T extends Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<SqlResult<T>> {
    const result = params.length ? await this.client.query<T>(sql, params) : await this.client.query<T>(sql);
    return { rows: result.rows };
  }
  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    return this.client.transaction(async (tx) => run({
      query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
        const result = params.length ? await tx.query<R>(sql, params) : await tx.query<R>(sql);
        return { rows: result.rows };
      },
      exec: async (sql: string) => {
        await tx.exec(sql);
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

const port = Number(process.env.PORT ?? "8787");
const origin = `http://127.0.0.1:${port}`;
const bootstrapToken = "dev-bootstrap-token-0123456789abcdef";
const database = new PGliteDatabase(new PGlite(process.env.DEV_PGLITE_DIR));
await migrate(database);

const config: SelfhostConfig = {
  databaseUrl: "pglite",
  publicBaseUrl: process.env.SELFHOST_PUBLIC_URL ?? origin,
  relaycastUrl: "http://127.0.0.1:1",
  relaycastPublicUrl: "https://relaycast.dev-selfhost.company",
  relayauthUrl: "http://127.0.0.1:1",
  relayhistoryUrl: "http://127.0.0.1:1",
  relayhistoryPublicUrl: "https://history.dev-selfhost.company",
  relayauthApiKey: "dev",
  bootstrapToken,
  encryptionKeyring: { active: { id: "dev", key: Buffer.alloc(32, 1) } },
  port,
  host: "127.0.0.1",
  internalServiceToken: null,
  oauthRedirectUrl: `${process.env.SELFHOST_PUBLIC_URL ?? origin}/api/v1/integrations/oauth/callback`,
  dashboardUrl: process.env.SELFHOST_DASHBOARD_URL ?? `${process.env.SELFHOST_PUBLIC_URL ?? origin}/`,
};
const license = loadLicense();
const store = new ControlPlaneStore(database, config.encryptionKeyring, 1);
const flows = new FlowsStore(database, config.encryptionKeyring, defaultFlowsConfig(), config.relaycastPublicUrl);
const admin = createAdminModule({
  config,
  database,
  keyring: config.encryptionKeyring,
  runtimeCredentialVerifier: gateCredentialVerifier((t: string) => flows.verifyRuntimeCredential(t), license, "flows"),
});
// Explicit operator-selected local provider. Never a browser-controlled module or auth bypass.
const chief: ChiefBackend | undefined = process.env.DEV_CHIEF_MODULE
  ? await (await import(pathToFileURL(process.env.DEV_CHIEF_MODULE).href)).createChiefBackend({
      dataDir: process.env.DEV_CHIEF_DATA_DIR,
    })
  : undefined;
const server = createServer(createApp({ config, store, flows, admin, chief, license }));
server.requestTimeout = 0;

const existing = await store.listOrganizations();
let organizationId = existing[0]?.id as string | undefined;
let ownerId: string | undefined;
if (!organizationId) {
  const org = await store.createOrganization({ name: "Dev", ownerEmail: "owner@dev.test", ownerName: "Dev Owner" });
  organizationId = org.id;
  ownerId = org.owner.id;
  await store.createWorkspace({
    organizationId,
    name: "Default",
    relaycastWorkspaceId: "dev-relaycast",
    relaycastApiKey: process.env.DEV_RELAYCAST_API_KEY ?? "rk_live_dev_placeholder",
  });
} else {
  ownerId = (await store.listMemberships(organizationId)).find((m) => m.role === "owner")?.userId as string;
}
const workspaceId = (await store.listWorkspaces(organizationId))[0]!.id as string;

server.listen(port, "127.0.0.1", () => {
  console.log(JSON.stringify({ origin, organizationId, ownerId, workspaceId }));
});
