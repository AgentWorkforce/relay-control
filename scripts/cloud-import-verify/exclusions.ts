/** Deliberate exclusions are narrow source predicates, not producer waivers.
 * Report fixed class names and counts only; never row IDs or credentials. */
export const DELIBERATE_CREDENTIAL_EXCLUSIONS=["unsupported_dropped","dead_login","unsupported_model_provider"] as const;
export type ExclusionFacts={reason:string;provider:unknown;authType:unknown;status?:unknown;refreshExhausted?:unknown};
export const exclusionAccounting=() => DELIBERATE_CREDENTIAL_EXCLUSIONS.map((reason) => ({reason,accounted:0,unresolved:0}));
export type ExclusionAccounting=ReturnType<typeof exclusionAccounting>;

export function accountCredentialExclusion(summary:ExclusionAccounting,facts:ExclusionFacts):boolean|null {
  const entry=summary.find((item) => item.reason === facts.reason);
  if (!entry) return null;
  const provider=typeof facts.provider === "string" ? facts.provider.trim().toLowerCase() : "";
  const secretBearing=["byo_api_key","oauth_token","provider_oauth"].includes(String(facts.authType));
  const accounted=facts.reason === "unsupported_dropped"
    ? facts.authType === "provider_oauth" && ["openrouter","daytona"].includes(provider)
      && facts.status === "connected" && facts.refreshExhausted === false
    : facts.reason === "dead_login"
      ? secretBearing && (facts.refreshExhausted === true
        || (["oauth_token","provider_oauth"].includes(String(facts.authType)) && facts.status === "refresh_failed"))
      : provider === "opencode" && facts.authType === "relay_managed";
  entry[accounted ? "accounted" : "unresolved"]++;
  return accounted;
}
