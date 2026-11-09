import { createMcpOidcIssuer, type McpOidcConfiguration } from "./oidc.js";

type Env = Record<string, string | undefined>;
export type McpOAuthConfig = {
  enabled: boolean;
  eventsEnabled: boolean;
  pumpEnabled: boolean;
  /** Null means OAuth without OpenID Connect; callers derive OIDC availability from this one value. */
  oidc: McpOidcConfiguration | null;
};

function flag(env: Env, name: string): boolean {
  const value=env[name]?.trim().toLowerCase() || "off";
  if(value!=="on" && value!=="off") throw new Error(`${name} must be on or off`);
  return value==="on";
}

/** Loads operator inputs only; it does not mount routes or start a scheduler. */
export function loadMcpOAuthConfig(env: Env, readSecret: (name:string)=>string|undefined): McpOAuthConfig {
  const enabled=flag(env,"SELFHOST_MCP_OAUTH");
  const eventsEnabled=flag(env,"SELFHOST_MCP_EVENTS");
  const pumpEnabled=flag(env,"SELFHOST_MCP_EVENTS_PUMP");
  if(pumpEnabled && !eventsEnabled) throw new Error("SELFHOST_MCP_EVENTS_PUMP requires SELFHOST_MCP_EVENTS=on");

  const keyId=env.SELFHOST_MCP_OIDC_SIGNING_KEY_ID?.trim();
  const privateKeyPem=readSecret("SELFHOST_MCP_OIDC_SIGNING_KEY");
  const subjectSalt=readSecret("SELFHOST_MCP_OIDC_SUBJECT_SALT");
  const previousJson=readSecret("SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS");
  let oidc:McpOidcConfiguration|null=null;
  if(keyId || privateKeyPem || subjectSalt || previousJson) {
    if(!keyId || !privateKeyPem || !subjectSalt) {
      throw new Error("MCP OIDC requires SELFHOST_MCP_OIDC_SIGNING_KEY_ID, SIGNING_KEY and SUBJECT_SALT (secrets may use _FILE)");
    }
    let previousPublicKeys:McpOidcConfiguration["previousPublicKeys"];
    if(previousJson) {
      let value:unknown;
      try { value=JSON.parse(previousJson); } catch { throw new Error("SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS must be a JSON array"); }
      if(!Array.isArray(value) || value.length>2 || value.some(entry=>!entry || typeof entry!=="object" ||
        typeof entry.kid!=="string" || typeof entry.expiresAt!=="string" || !entry.publicJwk || typeof entry.publicJwk!=="object")) {
        throw new Error("SELFHOST_MCP_OIDC_PREVIOUS_PUBLIC_KEYS must contain at most two public key entries with kid and expiresAt strings");
      }
      previousPublicKeys=value;
    }
    oidc={keyId,privateKeyPem,subjectSalt,...(previousPublicKeys?{previousPublicKeys}:{})};
    // Validate RSA strength, key IDs/material, public-only rotation keys and
    // expiry now. No signing material is included in configuration errors.
    try { createMcpOidcIssuer(oidc); } catch { throw new Error("MCP OIDC signing configuration is invalid; check the RSA key, key IDs, public rotation keys and expiry"); }
  }
  return {enabled,eventsEnabled,pumpEnabled,oidc};
}
