import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { ApiTokenStore } from "../admin/api-tokens.js";
import { recordAudit, type AuditActor } from "../admin/audit.js";
import { introspect, normalizedOrigin, WORKSPACE_API_TOKEN_PREFIX } from "../auth/introspect.js";
import type { AcquisitionIssuerConfig, SelfhostConfig } from "../config.js";
import { secureEqual } from "../crypto.js";
import type { ControlPlaneStore } from "../store.js";
import {
  AcquisitionAssertionError,
  acquisitionPayload,
  isAcquisitionUuid,
  signAcquisitionAssertion,
  type AcquisitionEnvelope,
  type AcquisitionOperation,
} from "./assertion.js";

/**
 * Dormant cloud-class acquisition assertion issuer (docs/acquisition-issuer.md).
 *
 * relaycontrol is the single issuer of acquisition assertions; the
 * RelayHistory pipeline (relayhistory-pipeline #331) only verifies them
 * against the keys published here and pinned in its ACQUISITION_PINNED_KEYS.
 *
 * - GET  /api/v1/acquisition/issuer-keys (unauthenticated)
 * - POST /api/v1/acquisition/assertions/{install|revoke|rebind}
 *
 * Off (no `config.acquisitionIssuer`): every /api/v1/acquisition path is
 * 404 not_found. Nothing is stored: issued assertions are not persisted,
 * only one audit row (no secrets, no signature) is written per issuance.
 * Errors are `{error:{code, message?}}`, the pipeline's shape.
 */
export const ACQUISITION_ISSUER_KEYS_PATH = "/api/v1/acquisition/issuer-keys";
const ACQUISITION_PREFIX = "/api/v1/acquisition";
const ASSERTION_PATH = /^\/api\/v1\/acquisition\/assertions\/([^/]+)$/;
const BODY_LIMIT = 64 * 1024;
export const ACQUIRE_SCOPE = "rth:acquire";
export const ACQUISITION_OPERATE_SCOPE = "acquisition:operate";
/** Control keys in the issuing request body, besides the unsigned payload fields. */
const CONTROL_KEYS = new Set(["aud", "reserveRevoke", "reservedRevoke"]);
const RESERVED_REVOKE_KEYS = ["operationUuid", "revision", "targetGrantId", "targetOwnerEpoch"];

class AcquisitionHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message?: string) {
    super(message ?? code);
  }
}

function reply(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  response.end(JSON.stringify(body));
}

function fail(response: ServerResponse, error: AcquisitionHttpError): void {
  reply(response, error.status, {
    error: error.message === error.code ? { code: error.code } : { code: error.code, message: error.message },
  });
}

function bearerToken(request: IncomingMessage): string | null {
  const match = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? "");
  return match?.[1]?.trim() || null;
}

async function jsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > BODY_LIMIT) continue; // drain, stop buffering
    chunks.push(buffer);
  }
  if (size > BODY_LIMIT) throw new AcquisitionHttpError(413, "payload_too_large", "Body exceeds 64 KiB");
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new AcquisitionHttpError(400, "invalid_request", "Body must be a JSON object");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AcquisitionHttpError(400, "invalid_request", "Body must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

type Caller =
  | { kind: "service"; tokenId: string; organizationId: string; workspaceId: string }
  | { kind: "desktop-user"; userId: string; organizationId: string; workspaceId: string };

const notAuthorized = (message?: string) => new AcquisitionHttpError(403, "not_authorized", message);
const unauthorized = (message: string) => new AcquisitionHttpError(401, "unauthorized", message);

/**
 * The caller, resolved through the introspection internals with
 * aud = SELFHOST_ACQUISITION_ORIGIN (no second token parser):
 * - `service`: an acquisition-operator workspace API token (`sh_wk_`) whose
 *   stored aud is the acquisition origin, scope acquisition:operate;
 * - `desktop-user`: a relaycontrol session (`sh_at_`) carrying rth:acquire,
 *   not a Desktop browser handoff, whose user is still a member of the
 *   session's workspace.
 * A missing, unknown, revoked or expired bearer, or a string of no
 * recognised token kind, is 401 unauthorized. Everything else (another
 * workspace API token, agent token, bootstrap or internal service token,
 * browser session without rth:acquire, wrong aud, handoff, non-member,
 * workspace mismatch) is 403 not_authorized.
 */
async function resolveCaller(
  config: SelfhostConfig,
  issuer: AcquisitionIssuerConfig,
  store: ControlPlaneStore,
  apiTokens: ApiTokenStore | undefined,
  request: IncomingMessage,
): Promise<Caller> {
  const token = bearerToken(request);
  if (!token) throw unauthorized("Bearer token required");
  const result = await introspect(config, store, { token, aud: issuer.origin }, apiTokens);
  if (!result.active) {
    // A real credential that is not an acquisition caller, or one bound to
    // another audience or workspace, is 403: an existing workspace API token
    // of another purpose (introspection says `wrong-kind` only when the sh_wk_
    // record exists), and the deployment's bootstrap and internal service
    // tokens. A missing, unknown, revoked or expired bearer, or a string of no
    // recognised kind, is not a credential at all: 401.
    if (
      result.reason === "audience" ||
      result.reason === "workspace" ||
      (result.reason === "wrong-kind" && token.startsWith(WORKSPACE_API_TOKEN_PREFIX)) ||
      secureEqual(token, config.bootstrapToken) ||
      (config.internalServiceToken !== null && secureEqual(token, config.internalServiceToken))
    ) {
      throw notAuthorized();
    }
    throw unauthorized("Token is not active");
  }
  if (result.principal_type === "service") {
    if (!result.scopes.includes(ACQUISITION_OPERATE_SCOPE) || normalizedOrigin(result.aud) !== issuer.origin) {
      throw notAuthorized();
    }
    return { kind: "service", tokenId: result.token_id, organizationId: result.org, workspaceId: result.workspace };
  }
  if (result.principal_type !== "desktop-user" || !result.scopes.includes(ACQUIRE_SCOPE)) throw notAuthorized();
  // Introspection does not see Desktop browser handoffs; like the capability
  // routes, a handoff redirect token (exchanged or not) gains no authority here.
  const principal = await store.authenticateAccessToken(token);
  if (!principal) throw unauthorized("Token is not active");
  if (principal.pendingHandoff || principal.handoff || principal.userId !== result.sub) {
    throw notAuthorized();
  }
  if (!await store.workspaceForUser(result.workspace, result.sub)) throw notAuthorized();
  return { kind: "desktop-user", userId: result.sub, organizationId: result.org, workspaceId: result.workspace };
}

function invalidRequest(message: string): AcquisitionHttpError {
  return new AcquisitionHttpError(400, "invalid_request", message);
}

/** Validate with the pipeline codec's rules; any refusal is 400 invalid_request. */
function validated(kind: AcquisitionOperation, unsigned: Record<string, unknown>) {
  try {
    return acquisitionPayload(kind, unsigned);
  } catch (error) {
    if (error instanceof AcquisitionAssertionError) {
      throw invalidRequest(`The ${kind} fields do not match the acquisition assertion contract`);
    }
    throw error;
  }
}

function sign(issuer: AcquisitionIssuerConfig, kind: AcquisitionOperation, payload: unknown): AcquisitionEnvelope {
  return signAcquisitionAssertion(kind, payload, issuer.privateKey);
}

async function issue(
  config: SelfhostConfig,
  issuer: AcquisitionIssuerConfig,
  store: ControlPlaneStore,
  apiTokens: ApiTokenStore | undefined,
  kind: AcquisitionOperation,
  request: IncomingMessage,
  now: () => Date,
): Promise<Record<string, unknown>> {
  const caller = await resolveCaller(config, issuer, store, apiTokens, request);
  if (kind === "rebind") {
    request.resume();
    throw new AcquisitionHttpError(
      409,
      "native_receiver_contract_pending",
      "rebind is native-class only in the pipeline codec; this issuer signs cloud-class assertions only (docs/acquisition-issuer.md, Native receiver contract)",
    );
  }
  if (caller.kind === "desktop-user" && kind !== "install") {
    // A revoke names no owner, so it cannot be bound to the calling user;
    // Desktop users get revokes only as the reserved revoke of their install.
    throw notAuthorized("Desktop users mint revokes only as reserveRevoke on their own install");
  }
  const body = await jsonBody(request);

  if (typeof body.aud !== "string" || !body.aud.trim()) {
    throw invalidRequest("aud must be the acquisition origin");
  }
  if (normalizedOrigin(body.aud) !== issuer.origin) throw notAuthorized("aud is not this deployment's acquisition origin");
  if ("issuerKeyId" in body && body.issuerKeyId !== issuer.keyId) {
    throw invalidRequest("issuerKeyId, when supplied, must be the active issuer key id");
  }
  const reserve = body.reserveRevoke;
  if (reserve !== undefined && typeof reserve !== "boolean") throw invalidRequest("reserveRevoke must be a boolean");
  if (reserve === true && kind !== "install") throw invalidRequest("reserveRevoke is accepted on install only");
  if ((reserve === true) !== (body.reservedRevoke !== undefined)) {
    throw invalidRequest("reservedRevoke is required with reserveRevoke: true and refused otherwise");
  }
  const unsigned: Record<string, unknown> = { issuerKeyId: issuer.keyId };
  for (const [key, value] of Object.entries(body)) {
    if (!CONTROL_KEYS.has(key) && key !== "issuerKeyId") unsigned[key] = value;
  }
  const payload = validated(kind, unsigned);

  // Class rule: cloud-class assertions only. Native needs the receiver
  // contract (docs/acquisition-issuer.md); no native key exists here.
  const declared = kind === "install" ? payload.ownerKind : payload.targetOwnerKind;
  if (declared !== "cloud") {
    throw invalidRequest(`${kind === "install" ? "ownerKind" : "targetOwnerKind"} must be cloud; native-class assertions await the native receiver contract`);
  }
  if (payload.orgId !== caller.organizationId || payload.workspaceId !== caller.workspaceId) {
    throw notAuthorized("orgId and workspaceId must be the caller's organization and workspace");
  }
  if (caller.kind === "desktop-user" && payload.ownerUserId !== caller.userId) {
    throw notAuthorized("ownerUserId must be the calling user");
  }

  let revoke: AcquisitionEnvelope | undefined;
  if (reserve === true) {
    const reserved = body.reservedRevoke;
    if (!reserved || typeof reserved !== "object" || Array.isArray(reserved)) {
      throw invalidRequest("reservedRevoke must be an object");
    }
    const fields = reserved as Record<string, unknown>;
    const keys = Object.keys(fields);
    const optional = keys.filter((key) => key !== "operationUuid");
    if (keys.some((key) => !RESERVED_REVOKE_KEYS.includes(key)) ||
        optional.length !== RESERVED_REVOKE_KEYS.length - 1) {
      throw invalidRequest("reservedRevoke takes exactly revision, targetGrantId, targetOwnerEpoch and an optional operationUuid");
    }
    const operationUuid = fields.operationUuid ?? randomUUID();
    if (!isAcquisitionUuid(operationUuid) || operationUuid === payload.operationUuid) {
      throw invalidRequest("reservedRevoke.operationUuid must be a fresh lowercase UUID, not the install's");
    }
    const revokePayload = validated("revoke", {
      operationUuid,
      orgId: payload.orgId,
      workspaceId: payload.workspaceId,
      source: payload.source,
      sessionId: payload.sessionId,
      revision: fields.revision,
      targetGrantId: fields.targetGrantId,
      targetOwnerEpoch: fields.targetOwnerEpoch,
      targetOwnerKind: payload.ownerKind,
      targetBindingUuid: payload.bindingUuid,
      targetInstallationId: payload.installationId,
      issuerKeyId: issuer.keyId,
    });
    revoke = sign(issuer, "revoke", revokePayload);
  }
  const envelope = sign(issuer, kind, payload);
  const issuedAt = now().toISOString();

  const actor: AuditActor = caller.kind === "service"
    ? { kind: "service", subject: caller.tokenId }
    : { kind: "user", userId: caller.userId };
  await recordAudit(store.database, {
    organizationId: caller.organizationId,
    workspaceId: caller.workspaceId,
    actor,
    action: "acquisition.assertion.issued",
    target: `${kind} ${payload.operationUuid} key ${issuer.keyId}` +
      (revoke ? ` reserved-revoke ${revoke.payload.operationUuid}` : ""),
  });

  return {
    kind,
    issuerKeyId: issuer.keyId,
    issuedAt,
    envelope,
    ...(revoke ? { revokeEnvelope: revoke } : {}),
  };
}

/** Handles /api/v1/acquisition/*; false when the path is not one of them. */
export async function handleAcquisitionRoutes(input: {
  config: SelfhostConfig;
  store: ControlPlaneStore;
  apiTokens?: ApiTokenStore;
  request: IncomingMessage;
  response: ServerResponse;
  method: string;
  path: string;
  now?: () => Date;
}): Promise<boolean> {
  const { config, request, response, method, path } = input;
  if (path !== ACQUISITION_PREFIX && !path.startsWith(`${ACQUISITION_PREFIX}/`)) return false;
  const issuer = config.acquisitionIssuer;
  try {
    if (!issuer) throw new AcquisitionHttpError(404, "not_found");
    if (path === ACQUISITION_ISSUER_KEYS_PATH) {
      if (method !== "GET") throw new AcquisitionHttpError(405, "method_not_allowed");
      reply(response, 200, { keys: issuer.publishedKeys });
      return true;
    }
    const kind = ASSERTION_PATH.exec(path)?.[1];
    if (kind !== "install" && kind !== "revoke" && kind !== "rebind") {
      throw new AcquisitionHttpError(404, "not_found");
    }
    if (method !== "POST") throw new AcquisitionHttpError(405, "method_not_allowed");
    reply(response, 200, await issue(
      config, issuer, input.store, input.apiTokens, kind, request, input.now ?? (() => new Date()),
    ));
  } catch (error) {
    if (!(error instanceof AcquisitionHttpError)) throw error;
    if (!request.readableEnded) request.resume();
    if (error.status === 405) response.setHeader("allow", path === ACQUISITION_ISSUER_KEYS_PATH ? "GET" : "POST");
    fail(response, error);
  }
  return true;
}
