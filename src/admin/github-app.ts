import { sign, type KeyObject } from "node:crypto";
import type { FetchLike } from "./connections.js";

export type GithubAppConfig = { appId: string; privateKey: KeyObject };

/** Only fixed codes/statuses escape this boundary; upstream text may echo secrets. */
export class GithubAppTokenError extends Error {
  constructor(readonly code: string, readonly status: number) {
    super(`GitHub App installation token unavailable (${code})`);
    this.name = "GithubAppTokenError";
  }
}

export async function mintGithubInstallationToken(
  app: GithubAppConfig,
  installationId: string,
  fetchImpl: FetchLike,
): Promise<{ accessToken: string; expiresAt: Date }> {
  if (!/^[1-9][0-9]{0,19}$/.test(installationId)) {
    throw new GithubAppTokenError("invalid_installation_id", 409);
  }
  const now = Math.floor(Date.now() / 1_000);
  let jwt: string;
  try {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({ iat: now - 60, exp: now + 540, iss: app.appId })).toString("base64url");
    const input = `${header}.${payload}`;
    jwt = `${input}.${sign("RSA-SHA256", Buffer.from(input), app.privateKey).toString("base64url")}`;
  } catch {
    throw new GithubAppTokenError("app_signing_failed", 503);
  }
  let response: Response;
  try {
    response = await fetchImpl(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
      headers: {
        authorization: `Bearer ${jwt}`,
        accept: "application/vnd.github+json",
        "content-type": "application/json",
        "user-agent": "relay-control",
        "x-github-api-version": "2022-11-28",
      },
      // Preserve the installation's granted repositories and permissions.
      body: "{}",
    });
  } catch {
    throw new GithubAppTokenError("github_unreachable", 503);
  }
  if (!response.ok) {
    const rateLimited = response.status === 429 || response.headers.get("x-ratelimit-remaining") === "0";
    throw new GithubAppTokenError(`github_http_${response.status}`, rateLimited || response.status >= 500 || response.status < 400 ? 503 : 409);
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new GithubAppTokenError("invalid_token_response", 503);
  }
  const data = body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : {};
  const expiresAt = typeof data.expires_at === "string" ? Date.parse(data.expires_at) : NaN;
  if (typeof data.token !== "string" || !data.token.trim() || /[\s\u0000-\u001f\u007f]/u.test(data.token) ||
      !Number.isFinite(expiresAt) || expiresAt <= Date.now() + 120_000 || expiresAt > Date.now() + 3_660_000) {
    throw new GithubAppTokenError("invalid_token_response", 503);
  }
  return { accessToken: data.token, expiresAt: new Date(expiresAt) };
}
