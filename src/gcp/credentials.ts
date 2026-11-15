// Google Cloud credentials for the Desktop feed's GCS object store
// (src/desktop-feed/storage.ts). Application Default Credentials as resolved
// on Google infrastructure: the metadata server, which is GKE Workload
// Identity's GKE metadata server on a pod, or the attached service account on
// GCE and Cloud Run. Static service-account keys (GOOGLE_APPLICATION_CREDENTIALS,
// inline JSON) are deliberately not read. Hand-rolled on fetch so self-host
// carries no Google SDK dependency.

type Env = Record<string, string | undefined>;
type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export class GcpCredentialError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "GcpCredentialError";
  }
}

export interface GcpCredentialProvider {
  /** An OAuth access token for the workload's service account. */
  accessToken(): Promise<string>;
  /** The service account's email (the signed-URL credential). */
  serviceAccountEmail(): Promise<string>;
  /**
   * RSA-SHA256 signature of `payload` by the service account's Google-managed
   * key, through IAM Credentials signBlob. Needs iam.serviceAccounts.signBlob
   * on the service account itself (roles/iam.serviceAccountTokenCreator).
   */
  signBlob(payload: Buffer): Promise<Buffer>;
}

const METADATA_TIMEOUT_MS = 5_000;
const IAM_TIMEOUT_MS = 10_000;
const SERVICE_ACCOUNT_EMAIL = /^[A-Za-z0-9._%+-]{1,128}@[A-Za-z0-9.-]{1,253}$/;
/** Google error statuses are short identifiers; anything else is not echoed. */
const GOOGLE_STATUS = /^[A-Z_]{1,64}$/;

/** The metadata server origin; GCE_METADATA_HOST is the standard ADC override (host[:port]). */
export function metadataOrigin(env: Env = process.env): string {
  const host = env.GCE_METADATA_HOST?.trim() || "metadata.google.internal";
  if (!/^[A-Za-z0-9.-]+(?::\d{1,5})?$|^\[[0-9a-fA-F:]+\](?::\d{1,5})?$/.test(host)) {
    throw new GcpCredentialError("GCE_METADATA_HOST is not a host[:port]");
  }
  return `http://${host}`;
}

/**
 * Metadata-server credentials. Tokens are cached until a minute before their
 * expiry with one refresh in flight; the email is read once.
 */
export class MetadataGcpCredentialProvider implements GcpCredentialProvider {
  #token: { value: string; expiresAt: number } | null = null;
  #pendingToken: Promise<string> | null = null;
  #email: Promise<string> | null = null;
  private readonly origin: string;
  constructor(
    private readonly options: {
      env?: Env;
      fetchImpl?: FetchLike;
      /** Override for tests; default https://iamcredentials.googleapis.com. */
      iamOrigin?: string;
      now?: () => number;
    } = {},
  ) {
    this.origin = metadataOrigin(options.env ?? process.env);
  }
  private get fetchImpl(): FetchLike {
    return this.options.fetchImpl ?? ((url, init) => fetch(url, init));
  }
  private now(): number {
    return this.options.now?.() ?? Date.now();
  }
  private async metadata(path: string): Promise<Response> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.origin}/computeMetadata/v1/instance/service-accounts/default/${path}`, {
        headers: { "metadata-flavor": "Google" },
        signal: AbortSignal.timeout(METADATA_TIMEOUT_MS),
        redirect: "error",
      });
    } catch {
      throw new GcpCredentialError("GCP metadata server is unreachable (Workload Identity or an attached service account is required)");
    }
    if (response.status !== 200 || response.headers.get("metadata-flavor") !== "Google") {
      await response.body?.cancel().catch(() => undefined);
      throw new GcpCredentialError(`GCP metadata server answered ${response.status}`, response.status);
    }
    return response;
  }

  async accessToken(): Promise<string> {
    if (this.#token && this.#token.expiresAt > this.now() + 60_000) return this.#token.value;
    this.#pendingToken ??= this.#refreshToken().finally(() => {
      this.#pendingToken = null;
    });
    return this.#pendingToken;
  }

  async #refreshToken(): Promise<string> {
    const response = await this.metadata("token");
    const body = (await response.json().catch(() => null)) as { access_token?: unknown; expires_in?: unknown } | null;
    if (!body || typeof body.access_token !== "string" || !body.access_token
      || typeof body.expires_in !== "number" || !(body.expires_in > 0)) {
      throw new GcpCredentialError("GCP metadata server returned no access token");
    }
    this.#token = { value: body.access_token, expiresAt: this.now() + body.expires_in * 1000 };
    return body.access_token;
  }

  serviceAccountEmail(): Promise<string> {
    this.#email ??= (async () => {
      const email = (await (await this.metadata("email")).text()).trim();
      if (!SERVICE_ACCOUNT_EMAIL.test(email)) throw new GcpCredentialError(
        "GCP metadata server returned no Google service account email; signed URLs need the Kubernetes ServiceAccount "
          + "linked to a Google service account (iam.gke.io/gcp-service-account) and annotated "
          + "iam.gke.io/return-principal-id-as-email=\"true\"",
      );
      return email;
    })().catch((error) => {
      this.#email = null;
      throw error;
    });
    return this.#email;
  }

  async signBlob(payload: Buffer): Promise<Buffer> {
    const [email, token] = await Promise.all([this.serviceAccountEmail(), this.accessToken()]);
    const origin = (this.options.iamOrigin ?? "https://iamcredentials.googleapis.com").replace(/\/+$/, "");
    let response: Response;
    try {
      response = await this.fetchImpl(
        `${origin}/v1/projects/-/serviceAccounts/${encodeURIComponent(email)}:signBlob`,
        {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ payload: payload.toString("base64") }),
          signal: AbortSignal.timeout(IAM_TIMEOUT_MS),
          redirect: "error",
        },
      );
    } catch {
      throw new GcpCredentialError("IAM Credentials signBlob is unreachable");
    }
    const body = (await response.json().catch(() => null)) as
      | { signedBlob?: unknown; error?: { status?: unknown } }
      | null;
    if (response.status !== 200 || !body || typeof body.signedBlob !== "string" || !body.signedBlob) {
      const status = typeof body?.error?.status === "string" && GOOGLE_STATUS.test(body.error.status) ? ` ${body.error.status}` : "";
      throw new GcpCredentialError(`IAM Credentials signBlob failed: ${response.status}${status}`, response.status);
    }
    return Buffer.from(body.signedBlob, "base64");
  }
}
