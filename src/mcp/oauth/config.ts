import { createMcpOidcIssuer, type McpOidcConfiguration } from "./oidc.js";
import { mcpOAuthPublicOriginAllowed } from "./protocol.js";

type Env = Record<string, string | undefined>;
/** Why an enabled connector flow cannot run; names an input, never a value. */
export type McpOAuthUnavailableReason = "public_url" | "oidc_signing_key";
export type McpOAuthConfig = {
  enabled: boolean;
  /** Non-null only when enabled: the OAuth surface answers 501 and no worker starts. */
  unavailable: null | {reason: McpOAuthUnavailableReason};
  eventsEnabled: boolean;
  pumpEnabled: boolean;
  /** Null means OAuth without OpenID Connect; callers derive OIDC availability from this one value. */
  oidc: McpOidcConfiguration | null;
};

const ON=new Set(["on","true","1"]),OFF=new Set(["off","false","0"]);
/** Unset or empty takes the default; any other unrecognized spelling is an operator typo and fails. */
function flag(env: Env, name: string, fallback: boolean): boolean {
  const value=env[name]?.trim().toLowerCase();
  if(!value) return fallback;
  if(!ON.has(value) && !OFF.has(value)) throw new Error(`${name} must be on or off`);
  return ON.has(value);
}

/** True when the connector flow is enabled and has every input it needs. */
export function mcpOAuthActive(config: {mcpOAuth?: McpOAuthConfig}): boolean {
  return config.mcpOAuth?.enabled===true && !config.mcpOAuth.unavailable;
}

class OidcUnavailable extends Error {}

/**
 * Loads operator inputs only; it does not mount routes or start a scheduler.
 * Missing or invalid inputs do not fail start-up: they mark the flow unavailable.
 * Flag typos and the pump-without-events combination still throw.
 */
export function loadMcpOAuthConfig(env: Env, readSecret: (name:string)=>string|undefined, publicBaseUrl?: string): McpOAuthConfig {
  const enabled=flag(env,"SELFHOST_MCP_OAUTH",true);
  const eventsEnabled=flag(env,"SELFHOST_MCP_EVENTS",false);
  const pumpEnabled=flag(env,"SELFHOST_MCP_EVENTS_PUMP",false);
  if(pumpEnabled && !eventsEnabled) throw new Error("SELFHOST_MCP_EVENTS_PUMP requires SELFHOST_MCP_EVENTS=on");
  let oidc:McpOidcConfiguration|null=null;
  let reason:McpOAuthUnavailableReason|null=null;
  try { oidc=loadOidc(env,readSecret); } catch(error) {
    if(!(error instanceof OidcUnavailable)) throw error;
    reason="oidc_signing_key";
  }
  if(publicBaseUrl!==undefined && !mcpOAuthPublicOriginAllowed(publicBaseUrl)) reason="public_url";
  return {enabled,unavailable:enabled && reason?{reason}:null,eventsEnabled,pumpEnabled,oidc:reason?null:oidc};
}

function loadOidc(env: Env, readSecret: (name:string)=>string|undefined): McpOidcConfiguration|null {
  const keyId=env.SELFHOST_MCP_OIDC_SIGNING_KEY_ID?.trim();
  const privateKeyPem=readSecret("SELFHOST_MCP_OIDC_SIGNING_KEY");
  const subjectSalt=readSecret("SELFHOST_MCP_OIDC_SUBJECT_SALT");
  const previousJson=readSecret("SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS");
  let oidc:McpOidcConfiguration|null=null;
  if(keyId || privateKeyPem || subjectSalt || previousJson) {
    if(!keyId || !privateKeyPem || !subjectSalt) {
      throw new OidcUnavailable("MCP OIDC requires SELFHOST_MCP_OIDC_SIGNING_KEY_ID, SIGNING_KEY and SUBJECT_SALT (secrets may use _FILE)");
    }
    let previousPublicKeys:McpOidcConfiguration["previousPublicKeys"];
    if(previousJson) {
      let value:unknown;
      try { value=JSON.parse(previousJson); } catch { throw new OidcUnavailable("SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS must be a JSON array"); }
      if(!Array.isArray(value) || value.length>2 || value.some(entry=>!entry || typeof entry!=="object" ||
        typeof entry.kid!=="string" || typeof entry.expiresAt!=="string" || !entry.publicJwk || typeof entry.publicJwk!=="object")) {
        throw new OidcUnavailable("SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS must contain at most two public key entries with kid and expiresAt strings");
      }
      previousPublicKeys=value;
    }
    oidc={keyId,privateKeyPem,subjectSalt,...(previousPublicKeys?{previousPublicKeys}:{})};
    // Validate RSA strength, key IDs/material, public-only rotation keys and
    // expiry now. No signing material is included in configuration errors.
    try { createMcpOidcIssuer(oidc); } catch { throw new OidcUnavailable("MCP OIDC signing configuration is invalid; check the RSA key, key IDs, public rotation keys and expiry"); }
  }
  return oidc;
}
