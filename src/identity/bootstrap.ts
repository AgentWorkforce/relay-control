import type { BootstrapConfig } from "./config.js";
import type { IdentityStore } from "./store.js";
import type { FetchLike } from "./oidc.js";
import { drainBody } from "../drain-body.js";

/** A cold durable-actors workspace create has taken ~100 s; leave headroom. */
const RELAYCAST_CREATE_TIMEOUT_MS = 300_000;
const RELAYCAST_CAPABILITIES_TIMEOUT_MS = 30_000;

const DEFINITE_CREATE_ERROR_CODES = new Set([
  "workspace_create_bootstrap_secret_invalid",
  "workspace_create_idempotency_conflict",
  "workspace_create_idempotency_digest_required",
  "workspace_create_idempotency_key_too_weak",
  "workspace_create_idempotency_owner_required",
  "workspace_create_idempotency_terminalized",
  "workspace_create_idempotency_unavailable",
]);

export type RelaycastWorkspace = { id: string; apiKey: string };

export interface RelaycastProvisioner {
  create(name: string, idempotencyKey?: string): Promise<RelaycastWorkspace>;
  remove(id: string): Promise<void>;
}

export class ProvisionError extends Error {
  constructor(message: string, readonly retryable: boolean, readonly outcomeUnknown = false) {
    super(message);
  }
}

/**
 * Relaycast's internal admin API (RELAYCAST_INTERNAL_SECRET): the same call
 * the Desktop e2e used to rebind Default by hand. On a durable-actors
 * Relaycast it returns an ar_ws_ key; on the SQLite image an rk_live_ key.
 */
export function relaycastProvisioner(
  relaycastUrl: string,
  internalSecret: string,
  fetchImpl: FetchLike = (input, init) => globalThis.fetch(input, init),
): RelaycastProvisioner {
  const base = relaycastUrl.replace(/\/+$/, "");
  const headers = { authorization: `Bearer ${internalSecret}`, "content-type": "application/json", accept: "application/json" };
  let idempotentCreateSupport: Promise<void> | null = null;

  const requireIdempotentCreate = async (): Promise<void> => {
    if (idempotentCreateSupport === null) {
      idempotentCreateSupport = (async () => {
        let response: Response;
        try {
          response = await fetchImpl(`${base}/internal/capabilities`, {
            method: "GET",
            headers,
            signal: AbortSignal.timeout(RELAYCAST_CAPABILITIES_TIMEOUT_MS),
          });
        } catch {
          throw new ProvisionError("Relaycast capability discovery is unreachable", true);
        }
        const body = await response.json().catch(() => null) as {
          data?: { workspace_admin?: { create_idempotency?: unknown } };
        } | null;
        if (response.status === 401 || response.status === 404) {
          throw new ProvisionError(
            response.status === 401
              ? "Relaycast refused RELAYCAST_INTERNAL_SECRET (it must equal relaycast's internal secret)"
              : "Relaycast has no internal admin capability API",
            true,
          );
        }
        if (!response.ok) {
          throw new ProvisionError(
            `Relaycast capability discovery answered ${response.status}`,
            response.status >= 500 || response.status === 429,
          );
        }
        if (body?.data?.workspace_admin?.create_idempotency !== true) {
          throw new ProvisionError(
            "Relaycast does not advertise idempotent internal workspace creation",
            true,
          );
        }
      })();
    }
    try {
      await idempotentCreateSupport;
    } catch (error) {
      // A rolling Relaycast upgrade may add the capability later. Fail this
      // create before mutation, but let a later first-use retry discovery.
      idempotentCreateSupport = null;
      throw error;
    }
  };

  return {
    async create(name, idempotencyKey) {
      // Lazy bindings recover an uncertain response by replaying this key.
      // Refuse to mutate older engines which accept but ignore the header.
      if (idempotencyKey) await requireIdempotentCreate();
      let response: Response;
      try {
        response = await fetchImpl(`${base}/internal/workspaces`, {
          method: "POST",
          headers: { ...headers, ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}) },
          body: JSON.stringify({ name: name.slice(0, 128) }),
          signal: AbortSignal.timeout(RELAYCAST_CREATE_TIMEOUT_MS),
        });
      } catch {
        // The request may have reached Relaycast. Callers with a durable
        // claim retry with the same idempotency key instead of deleting or
        // creating under a new identity.
        throw new ProvisionError("Relaycast is unreachable", true, true);
      }
      const body = await response.json().catch(() => null) as {
        data?: { workspace_id?: unknown; api_key?: unknown };
        error?: { code?: unknown };
      } | null;
      if (response.status === 401 || response.status === 404) {
        throw new ProvisionError(
          response.status === 401
            ? "Relaycast refused RELAYCAST_INTERNAL_SECRET (it must equal relaycast's internal secret)"
            : "Relaycast has no internal admin API (set RELAYCAST_INTERNAL_SECRET on relaycast too)",
          // A rollout may bring relaycast's secret into line; keep trying slowly.
          true,
        );
      }
      if (response.status !== 201 && response.status !== 200) {
        const errorCode = typeof body?.error?.code === "string" ? body.error.code : null;
        const outcomeUnknown = response.status >= 500
          && (errorCode === null || !DEFINITE_CREATE_ERROR_CODES.has(errorCode));
        throw new ProvisionError(
          `Relaycast workspace create answered ${response.status}${errorCode ? ` (${errorCode})` : ""}`,
          response.status >= 500 || response.status === 429,
          outcomeUnknown,
        );
      }
      const id = body?.data?.workspace_id;
      const apiKey = body?.data?.api_key;
      if (typeof id !== "string" || !id || typeof apiKey !== "string" || !apiKey) {
        // A successful create response with an unusable body can still have
        // committed remotely. Preserve the claim and retry the stable key.
        throw new ProvisionError("Relaycast workspace create returned no workspace id or key", true, true);
      }
      return { id, apiKey };
    },
    async remove(id) {
      let response: Response;
      try {
        response = await fetchImpl(`${base}/internal/workspaces/${encodeURIComponent(id)}`, {
          method: "DELETE",
          headers,
          signal: AbortSignal.timeout(30_000),
        });
      } catch {
        throw new ProvisionError(`Relaycast workspace ${id} cleanup is unreachable`, true, true);
      }
      if (!response.ok && response.status !== 404) {
        throw new ProvisionError(
          `Relaycast workspace ${id} cleanup answered ${response.status}`,
          response.status >= 500 || response.status === 429,
          response.status >= 500,
        );
      }
      await drainBody(response, "bootstrap.relaycast.workspace-remove");
    },
  };
}

export type BootstrapLogger = (message: string, fields?: Record<string, unknown>) => void;

/**
 * One idempotent bootstrap pass:
 *   - creates the organization (admin email = owner) when there is none, or
 *     grants owner to a newly configured admin email once;
 *   - provisions the default workspace and its Relaycast binding when the
 *     organization has no workspace yet.
 * Returns "done", or "pending" when the workspace could not be provisioned
 * yet (the caller retries).
 */
export async function bootstrapOnce(input: {
  bootstrap: BootstrapConfig;
  store: IdentityStore;
  provisioner: RelaycastProvisioner | null;
  log: BootstrapLogger;
}): Promise<"done" | "pending"> {
  const { bootstrap, store, provisioner, log } = input;
  const organization = await store.ensureOrganization(bootstrap);
  if (organization.organizationId === null) {
    // Single mode over a multi-organization database: readiness reports
    // tenancy_mismatch and bootstrap changes nothing until it is resolved.
    log("bootstrap skipped: SELFHOST_TENANCY=single but more than one organization exists", { organizations: organization.organizations });
    return "done";
  }
  if (organization.created) {
    log("organization created", { organizationId: organization.organizationId, owner: bootstrap.adminEmail });
  } else if (organization.adminGranted) {
    log("bootstrap admin granted owner", { organizationId: organization.organizationId, owner: bootstrap.adminEmail });
  }
  if (await store.workspaceCount(organization.organizationId) > 0) return "done";
  if (!provisioner) {
    log("default workspace not created: set RELAYCAST_INTERNAL_SECRET (relay-cloud-api secretKeys.relaycastInternalSecret) so the API can create its Relaycast workspace");
    return "done";
  }
  const relaycast = await provisioner.create(bootstrap.workspaceName);
  const stored = await store.insertBootstrapWorkspace({
    organizationId: organization.organizationId,
    name: bootstrap.workspaceName,
    relaycastWorkspaceId: relaycast.id,
    relaycastApiKey: relaycast.apiKey,
  });
  if (!stored) {
    // Another path created a workspace meanwhile; drop the unused binding.
    await provisioner.remove(relaycast.id);
    return "done";
  }
  log("default workspace created", { workspaceId: stored.id, relaycastWorkspaceId: relaycast.id, name: bootstrap.workspaceName });
  return "done";
}

/**
 * Runs bootstrapOnce until it completes, backing off 5 s → 60 s. Never
 * throws: the API keeps serving (break-glass included) while Relaycast is
 * still starting.
 */
export function startBootstrap(input: Parameters<typeof bootstrapOnce>[0] & {
  sleep?: (ms: number) => Promise<void>;
  signal?: AbortSignal;
}): Promise<void> {
  const sleep = input.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms).unref()));
  return (async () => {
    let delay = 5_000;
    for (let attempt = 1; !input.signal?.aborted; attempt += 1) {
      try {
        if (await bootstrapOnce(input) === "done") return;
      } catch (error) {
        const retryable = !(error instanceof ProvisionError) || error.retryable;
        input.log("bootstrap attempt failed", {
          attempt,
          error: error instanceof Error ? error.message : String(error),
          retryInMs: retryable ? delay : null,
        });
        if (!retryable) return;
      }
      await sleep(delay);
      delay = Math.min(60_000, delay * 2);
    }
  })();
}
