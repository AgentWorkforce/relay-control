#!/usr/bin/env node
import { createServer } from "node:http";
import { browserOriginsFor, createApp } from "./app.js";
import { createFactoryModule } from "./factory/routes.js";
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
import { FEATURES, gateCredentialVerifier, loadSelectedFeatures } from "./features.js";
import { loadAmpConfig } from "./amp/config.js";
import { createAmpModule } from "./amp/module.js";
import { McpOAuthTeardown,mcpOAuthTeardownFetch } from "./mcp/oauth/teardown.js";
import { mcpOAuthActive } from "./mcp/oauth/config.js";
import { mcpOAuthActiveNotice } from "./mcp/oauth/routes.js";
import { createRelaycastClient } from "./messaging/relaycast.js";
import { loadAnalyticsConfig } from "./analytics/config.js";
import {
  buildAnalytics,
  emitConfigLoaded,
  emitServiceStarted,
  emitStopping,
} from "./analytics/lifecycle.js";

const config = loadConfig();
// An unknown SELFHOST_FEATURES name stops startup.
const features = loadSelectedFeatures();
console.log("[selfhost-api] features selected", FEATURES.filter((feature) => features[feature]));
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
  // SELFHOST_ADMIN_EMAILS; the SELFHOST_BOOTSTRAP_ADMIN_EMAIL alias is the boot-time owner.
  adminEmails: identityConfig.bootstrap?.adminEmails.filter((email) => email !== identityConfig.bootstrap?.adminEmail) ?? [],
});
const identity = createIdentityModule({
  config: identityConfig,
  identityStore,
  controlStore: store,
  database,
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
  // Refused with the Flows feature code while Flows is not selected.
  runtimeCredentialVerifier: gateCredentialVerifier((t: string) => flows.verifyRuntimeCredential(t), features, "flows"),
});
// Subscription logins reach runs through a reference in the assignment payload.
flows.cliCredentials = admin.logins;
const telemetryConfig = loadTelemetryConfig(process.env, {
  probes: [
    { name: "relaycast", url: `${config.relaycastUrl}/health` },
    // RelayAuth is optional: without it History introspects relaycontrol tokens.
    ...(config.relayauthUrl ? [{ name: "relayauth", url: `${config.relayauthUrl}/health` }] : []),
    // The read API has only /healthz; native has no separate History service.
    { name: "relayhistory", url: `${config.relayhistoryUrl}/${config.relayhistoryBackend === "native" ? "healthz" : "readyz"}` },
  ],
});
const relaycontrolVersion = process.env.SELFHOST_IMAGE_VERSION?.trim() || SELFHOST_API_VERSION;
const telemetry = createTelemetryModule({
  config: telemetryConfig,
  database,
  keyring: config.encryptionKeyring,
  relaycontrolVersion,
  relaycastUrl: config.relaycastUrl,
  audit: (event) => recordAudit(database, event),
  tenancy: identityConfig.tenancy.mode,
});
// Amp control: off unless SELFHOST_AMP_ENABLED=true; off starts no worker.
const amp = createAmpModule({ amp: loadAmpConfig(process.env), config, database });
const mcpOAuthTeardown = new McpOAuthTeardown({
  database,keyring:config.encryptionKeyring,
  client:createRelaycastClient({internalOrigin:config.relaycastUrl,fetchImpl:mcpOAuthTeardownFetch()}),
});
// Factory sessions: routes 404 and the worker stays off unless SELFHOST_FACTORY_ENABLED.
const factory = createFactoryModule({
  config,
  database,
  messaging: { database, keyring: config.encryptionKeyring, relaycastUrl: config.relaycastUrl },
  browserOrigins: browserOriginsFor(config),
});
// Product analytics: a separate, bounded port. Export failures never fail the product.
const analyticsConfig = loadAnalyticsConfig(process.env);
const analytics = buildAnalytics(analyticsConfig);
emitConfigLoaded(analytics, {
  telemetry: telemetryConfig,
  signIn: {
    oidc: identityConfig.oidc !== null,
    emailLink: identityConfig.emailLogin,
    smtp: identityConfig.smtp !== null,
  },
  // The flows module is always mounted in this binary.
  flowsEnabled: true,
  operatorOAuthApps: Object.keys(config.operatorOAuthApps ?? {}).length,
});
const server = createServer(createApp({
  config,
  store,
  flows,
  admin,
  telemetry,
  identity,
  factory,
  features,
  amp,
  analytics: { port: analytics, config: analyticsConfig },
  mcpOAuthTeardown,
}));
const bootstrapAbort = new AbortController();
// Worker queue streams are long-lived SSE responses.
server.requestTimeout = 0;
server.headersTimeout = 65_000;

async function start(): Promise<void> {
  telemetry.start();
  identity.start();
  amp.start();
  if(mcpOAuthActive(config)) {
    console.log("[selfhost-api] hosted MCP OAuth active", mcpOAuthActiveNotice());
    mcpOAuthTeardown.start();
  }
  else if(config.mcpOAuth?.unavailable) console.warn("[selfhost-api] hosted MCP OAuth unavailable", { reason: config.mcpOAuth.unavailable.reason, detail: config.mcpOAuth.unavailable.detail });
  factory.start();
  server.listen(config.port, config.host, () => {
    console.log("[selfhost-api] listening", {
      host: config.host,
      port: config.port,
      config: configFingerprint(config),
      tenancy: identityConfig.tenancy,
      signIn: {
        oidc: identityConfig.oidc ? identityConfig.oidc.issuer : null,
        emailLink: identityConfig.emailLogin,
        password: identityConfig.signinMethods.includes("password"),
        smtp: identityConfig.smtp !== null,
        autoJoinDomains: identityConfig.autoJoinDomains.length,
      },
      amp: {
        enabled: amp.config.enabled,
        transport: amp.config.transport !== null,
        internalJob: amp.config.internalSecret !== null,
      },
    });
    emitServiceStarted(analytics, {
      componentVersion: relaycontrolVersion,
      configFingerprint: configFingerprint(config),
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
  // Set first: whatever happens below, the process must not exit 0.
  process.exitCode = 1;
  console.error("[selfhost-api] startup failed", {
    error: error instanceof Error ? error.message : String(error),
  });
  // The flush deadline timer holds the process open, so this completes or
  // times out (SHUTDOWN_DEADLINE_MS) before exit.
  await emitStopping(analytics, "startup_failed", analyticsConfig.shutdownDeadlineMs);
  await database.close();
});

async function shutdown(signal: "SIGINT" | "SIGTERM"): Promise<void> {
  // One 10 s budget for the whole sequence: telemetry stop, analytics flush
  // (SHUTDOWN_DEADLINE_MS, at most 8 s), server.close and database.close.
  setTimeout(() => process.exit(1), 10_000).unref();
  console.log("[selfhost-api] shutting down", { signal });
  bootstrapAbort.abort();
  await telemetry.stop();
  await amp.stop();
  await mcpOAuthTeardown.stop();
  await factory.stop();
  identity.stop();
  await emitStopping(analytics, signal, analyticsConfig.shutdownDeadlineMs);
  server.close(async () => {
    await database.close();
    process.exit(0);
  });
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
