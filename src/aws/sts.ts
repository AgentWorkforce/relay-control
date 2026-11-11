// AWS STS AssumeRole over the query API, signed with the hand-rolled SigV4
// helper (src/aws/sigv4.ts), so self-host carries no AWS SDK. Used by the
// direct-to-S3 session upload credentials (src/history-upload/credentials.ts).
// Credential values, the session policy and response bodies never go into
// error messages.
import { DefaultAwsCredentialProvider, encodeRfc3986, signV4, type AwsCredentialProvider } from "./sigv4.js";

export interface AssumedCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiresAt: Date;
}

export interface AssumeRoleInput {
  roleArn: string;
  roleSessionName: string;
  sourceIdentity: string;
  /** Inline session policy (JSON). */
  policy: string;
  durationSeconds: number;
}

export interface StsClient {
  assumeRole(input: AssumeRoleInput): Promise<AssumedCredentials>;
}

export class StsError extends Error {
  constructor(message: string, readonly code: string, readonly status?: number) {
    super(message);
    this.name = "StsError";
  }
}

const STS_TIMEOUT_MS = 10_000;
/** AWS error codes are short identifiers; anything else is not echoed. */
const AWS_ERROR_CODE = /^[A-Za-z0-9._-]{1,64}$/;

function xmlUnescape(value: string): string {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function xmlElement(xml: string, name: string): string | null {
  const match = new RegExp(`<${name}>([^<]*)</${name}>`).exec(xml);
  const value = match ? xmlUnescape(match[1]!.trim()) : "";
  return value || null;
}

export class AwsStsClient implements StsClient {
  constructor(
    private readonly options: {
      region: string;
      credentials?: AwsCredentialProvider;
      /** Override for tests; default https://sts.<region>.amazonaws.com. */
      endpoint?: string;
      fetchImpl?: typeof fetch;
      now?: () => Date;
    },
  ) {
    if (!/^[a-z0-9-]+$/.test(options.region)) throw new Error("STS region is not a region");
  }

  #credentials: AwsCredentialProvider | null = null;

  async assumeRole(input: AssumeRoleInput): Promise<AssumedCredentials> {
    const base = (this.options.endpoint ?? `https://sts.${this.options.region}.amazonaws.com`).replace(/\/+$/, "");
    const url = new URL(`${base}/`);
    const params: Record<string, string> = {
      Action: "AssumeRole",
      DurationSeconds: String(input.durationSeconds),
      Policy: input.policy,
      RoleArn: input.roleArn,
      RoleSessionName: input.roleSessionName,
      SourceIdentity: input.sourceIdentity,
      Version: "2011-06-15",
    };
    const body = Object.keys(params)
      .sort()
      .map((name) => `${encodeRfc3986(name)}=${encodeRfc3986(params[name]!)}`)
      .join("&");
    let response: Response;
    let text: string;
    try {
      const credentials = await (this.#credentials ??= this.options.credentials ?? new DefaultAwsCredentialProvider()).get();
      const headers = signV4({
        method: "POST",
        url,
        region: this.options.region,
        service: "sts",
        body,
        credentials,
        now: this.options.now?.() ?? new Date(),
        contentSha256Header: false,
        extraHeaders: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
      });
      response = await (this.options.fetchImpl ?? fetch)(url.toString(), {
        method: "POST",
        headers,
        body,
        signal: AbortSignal.timeout(STS_TIMEOUT_MS),
      });
      text = await response.text();
    } catch {
      throw new StsError("AssumeRole request failed", "unreachable");
    }
    if (!response.ok) {
      const code = xmlElement(text, "Code");
      throw new StsError(
        "AssumeRole refused",
        code && AWS_ERROR_CODE.test(code) ? code : `http_${response.status}`,
        response.status,
      );
    }
    const accessKeyId = xmlElement(text, "AccessKeyId");
    const secretAccessKey = xmlElement(text, "SecretAccessKey");
    const sessionToken = xmlElement(text, "SessionToken");
    const expiration = xmlElement(text, "Expiration");
    const expiresAt = expiration ? new Date(expiration) : null;
    if (!accessKeyId || !secretAccessKey || !sessionToken || !expiresAt || Number.isNaN(expiresAt.getTime())) {
      throw new StsError("AssumeRole response is incomplete", "malformed_response");
    }
    return { accessKeyId, secretAccessKey, sessionToken, expiresAt };
  }
}
