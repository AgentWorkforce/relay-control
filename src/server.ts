#!/usr/bin/env node
import { createServer } from "node:http";
import { createApp } from "./app.js";
import { createAdminModule } from "./admin/routes.js";
import { recordAudit } from "./admin/audit.js";
import { configFingerprint, loadConfig, SELFHOST_API_VERSION } from "./config.js";
import { PostgresDatabase } from "./database.js";
import { ControlPlaneStore } from "./store.js";
import { loadFlowsConfig } from "./flows/config.js";
import { FlowsStore } from "./flows/store.js";
import { loadTelemetryConfig } from "./telemetry/config.js";
import { createTelemetryModule } from "./telemetry/module.js";
import { loadIdentityConfig } from "./identity/config.js";
import { IdentityStore } from "./identity/store.js";
import { smtpMailer } from "./identity/mailer.js";
import { createIdentityModule } from "./identity/routes.js";
import { relaycastProvisioner, startBootstrap } from "./identity/bootstrap.js";

const config = loadConfig();
const database = new PostgresDatabase(config.databaseUrl);

// bootstrap-signup lane: first-boot org/workspace, OIDC/email sign-in, invites.
const identityConfig = loadIdentityConfig();
const store = new ControlPlaneStore(database, config.encryptionKeyring, undefined, {
  tenancy: identityConfig.tenancy.mode,
});
// Creates Relaycast workspaces for the bootstrap and (multi mode) personal
// and self-serve organizations; null without RELAYCAST_INTERNAL_SECRET.
const provisioner = identityConfig.relaycastInternalSecret
  ? relaycastProvisioner(config.relaycastUrl, identityConfig.relaycastInternalSecret)
  : null;
const identityStore = new IdentityStore(database, config.encryptionKeyring, {
  inviteTtlMs: identityConfig.inviteTtlMs,
  autoJoinDomains: identityConfig.autoJoinDomains,
  tenancy: identityConfig.tenancy,
  ...(provisioner ? { provisioner } : {}),
  issueSession: (tx, session) => store.issueBrowserSession(tx, session),
});
const identity = createIdentityModule({
  config: identityConfig,
  identityStore,
  controlStore: store,
  keyring: config.encryptionKeyring,
  dashboardUrl: config.dashboardUrl,
  mailer: identityConfig.smtp ? smtpMailer(identityConfig.smtp) : null,
});
const flows = new FlowsStore(
  database,
  config.encryptionKeyring,
  loadFlowsConfig(),
  config.relaycastPublicUrl,
);
const admin = createAdminModule({
  config,
  database,
  keyring: config.encryptionKeyring,
  // Flows worker credentials may read their own workspace's runtime environment.
  runtimeCredentialVerifier: (t) => flows.verifyRuntimeCredential(t),
});
// Subscription logins reach runs through a reference in the assignment payload.
flows.cliCredentials = admin.logins;
const telemetry = createTelemetryModule({
  config: loadTelemetryConfig(process.env, {
    probes: [
      { name: "relaycast", url: `${config.relaycastUrl}/health` },
      // RelayAuth is optional: without it History introspects relaycontrol tokens.
      ...(config.relayauthUrl ? [{ name: "relayauth", url: `${config.relayauthUrl}/health` }] : []),
      { name: "relayhistory", url: `${config.relayhistoryUrl}/readyz` },
    ],
  }),
  database,
  keyring: config.encryptionKeyring,
  relaycontrolVersion: process.env.SELFHOST_IMAGE_VERSION?.trim() || SELFHOST_API_VERSION,
  relaycastUrl: config.relaycastUrl,
  audit: (event) => recordAudit(database, event),
  tenancy: identityConfig.tenancy.mode,
});
const server = createServer(createApp({ config, store, flows, admin, telemetry, identity }));
const bootstrapAbort = new AbortController();
// Worker queue streams are long-lived SSE responses.
server.requestTimeout = 0;
server.headersTimeout = 65_000;

async function start(): Promise<void> {
  telemetry.start();
  server.listen(config.port, config.host, () => {
    console.log("[selfhost-api] listening", {
      host: config.host,
      port: config.port,
      config: configFingerprint(config),
      tenancy: identityConfig.tenancy,
      signIn: {
        oidc: identityConfig.oidc ? identityConfig.oidc.issuer : null,
        emailLink: identityConfig.emailLogin,
        smtp: identityConfig.smtp !== null,
        autoJoinDomains: identityConfig.autoJoinDomains.length,
      },
    });
  });
  if (identityConfig.bootstrap) {
    // In the background: Relaycast may still be starting; the API (and the
    // bootstrap-token break-glass) serve meanwhile.
    void startBootstrap({
      bootstrap: identityConfig.bootstrap,
      store: identityStore,
      provisioner,
      log: (message, fields) => console.log(`[selfhost-api] bootstrap: ${message}`, fields ?? {}),
      signal: bootstrapAbort.signal,
    });
  }
}

void start().catch(async (error: unknown) => {
  console.error("[selfhost-api] startup failed", {
    error: error instanceof Error ? error.message : String(error),
  });
  await database.close();
  process.exitCode = 1;
});

async function shutdown(signal: string): Promise<void> {
  console.log("[selfhost-api] shutting down", { signal });
  bootstrapAbort.abort();
  await telemetry.stop();
  server.close(async () => {
    await database.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
