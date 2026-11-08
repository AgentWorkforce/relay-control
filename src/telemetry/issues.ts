// telemetry lane: customer-side "report an issue". Operators and their agents
// file a scrubbed diagnostic report that rides the same signed channel as the
// digests. The optional support bundle reuses the document names and manifest
// flags of helm-charts scripts/support/collect-support-bundle.py.
import { scrubFreeText } from "./scrub.js";

export class IssueValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IssueValidationError";
  }
}

export const ISSUE_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export const ISSUE_CATEGORIES = ["bug", "outage", "performance", "upgrade", "configuration", "question"] as const;

/** Documents produced by collect-support-bundle.py that may be attached. */
export const SUPPORT_BUNDLE_DOCUMENTS = [
  "versions.json",
  "configuration-fingerprint.json",
  "workload-status.json",
  "migration-ledger-status.json",
  "resource-pressure.json",
  "backup-age.json",
  "network-health.json",
  "correlation-ids.json",
  "release-evidence.json",
  "collection-errors.json",
] as const;

/** Manifest flags from the bundle that are worth carrying (all booleans/short). */
const MANIFEST_FIELDS = [
  "schemaVersion",
  "collectorVersion",
  "collectedAt",
  "readOnly",
  "kubernetesSecretsCollected",
  "secretPayloadsIncluded",
  "passwordBearingUrlsBlocked",
  "rawLogsIncluded",
  "rawManifestsIncluded",
  "rawHelmValuesIncluded",
] as const;

const MAX_DOCUMENT_BYTES = 64 * 1024;
const MAX_BUNDLE_BYTES = 256 * 1024;

export type IssueInput = {
  title: string;
  summary: string;
  severity: (typeof ISSUE_SEVERITIES)[number];
  category: (typeof ISSUE_CATEGORIES)[number];
  component: string | null;
  stepsToReproduce: string | null;
  expected: string | null;
  observed: string | null;
  supportBundle: Record<string, unknown> | null;
  dryRun: boolean;
};

function text(body: Record<string, unknown>, name: string, max: number, required: boolean): string | null {
  const value = body[name];
  if (value === undefined || value === null || value === "") {
    if (required) throw new IssueValidationError(`${name} is required`);
    return null;
  }
  if (typeof value !== "string") throw new IssueValidationError(`${name} must be a string`);
  const cleaned = value.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, " ").trim();
  if (!cleaned && required) throw new IssueValidationError(`${name} is required`);
  if (cleaned.length > max) throw new IssueValidationError(`${name} must be at most ${max} characters`);
  return cleaned || null;
}

function oneOf<T extends string>(body: Record<string, unknown>, name: string, values: readonly T[], fallback: T): T {
  const value = body[name];
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value !== "string" || !values.includes(value as T)) {
    throw new IssueValidationError(`${name} must be one of ${values.join(", ")}`);
  }
  return value as T;
}

export function parseIssue(body: Record<string, unknown>): IssueInput {
  const component = text(body, "component", 40, false);
  if (component && !/^[a-z][a-z0-9-]{0,39}$/.test(component)) {
    throw new IssueValidationError("component must be a lowercase service name such as relayhistory");
  }
  const supportBundle = body.supportBundle;
  if (supportBundle !== undefined && supportBundle !== null &&
    (typeof supportBundle !== "object" || Array.isArray(supportBundle))) {
    throw new IssueValidationError("supportBundle must be an object");
  }
  return {
    title: text(body, "title", 200, true)!,
    summary: text(body, "summary", 4000, true)!,
    severity: oneOf(body, "severity", ISSUE_SEVERITIES, "medium"),
    category: oneOf(body, "category", ISSUE_CATEGORIES, "bug"),
    component,
    stepsToReproduce: text(body, "stepsToReproduce", 4000, false),
    expected: text(body, "expected", 2000, false),
    observed: text(body, "observed", 2000, false),
    supportBundle: (supportBundle as Record<string, unknown> | undefined) ?? null,
    dryRun: body.dryRun === true,
  };
}

/**
 * Keep only known bundle documents, each size-bounded. Accepts either the
 * `{manifest, documents}` shape or a flat `{ "versions.json": {...} }` map.
 */
export function sanitizeSupportBundle(input: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!input) return null;
  const documentsSource = input.documents && typeof input.documents === "object" && !Array.isArray(input.documents)
    ? input.documents as Record<string, unknown>
    : input;
  const manifestSource = input.manifest && typeof input.manifest === "object" && !Array.isArray(input.manifest)
    ? input.manifest as Record<string, unknown>
    : {};
  const manifest: Record<string, unknown> = {};
  for (const field of MANIFEST_FIELDS) {
    const value = manifestSource[field];
    if (typeof value === "boolean" || typeof value === "number") manifest[field] = value;
    else if (typeof value === "string" && value.length <= 64) manifest[field] = value;
  }
  const documents: Record<string, unknown> = {};
  const omitted: string[] = [];
  let total = 0;
  for (const name of SUPPORT_BUNDLE_DOCUMENTS) {
    if (!(name in documentsSource)) continue;
    const serialized = JSON.stringify(documentsSource[name]) ?? "null";
    const size = Buffer.byteLength(serialized);
    if (size > MAX_DOCUMENT_BYTES || total + size > MAX_BUNDLE_BYTES) {
      omitted.push(name);
      continue;
    }
    total += size;
    documents[name] = documentsSource[name];
  }
  const ignored = Object.keys(documentsSource).filter(
    (name) => !(SUPPORT_BUNDLE_DOCUMENTS as readonly string[]).includes(name) && name !== "manifest",
  ).length;
  return { manifest, documents, omittedForSize: omitted, ignoredDocuments: ignored };
}

export function issueSection(issue: IssueInput): Record<string, unknown> {
  // Free text is explicitly provided by the customer; it is still scrubbed.
  return {
    title: scrubFreeText(issue.title),
    summary: scrubFreeText(issue.summary),
    severity: issue.severity,
    category: issue.category,
    component: issue.component,
    stepsToReproduce: issue.stepsToReproduce ? scrubFreeText(issue.stepsToReproduce) : null,
    expected: issue.expected ? scrubFreeText(issue.expected) : null,
    observed: issue.observed ? scrubFreeText(issue.observed) : null,
  };
}

/** MCP tool definition for the customer's agents (also in docs/telemetry.md). */
export const REPORT_ISSUE_TOOL = {
  name: "report_selfhost_issue",
  description:
    "File a diagnostic issue report with Agent Relay support from this self-hosted install. " +
    "Include what failed and when. Do not include message content, transcripts, prompts, " +
    "file contents, secrets, emails, or user names; the report is scrubbed but keep it minimal. " +
    "Set dryRun=true to see exactly what would be sent without sending it.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["title", "summary"],
    properties: {
      title: { type: "string", maxLength: 200 },
      summary: { type: "string", maxLength: 4000 },
      severity: { type: "string", enum: [...ISSUE_SEVERITIES], default: "medium" },
      category: { type: "string", enum: [...ISSUE_CATEGORIES], default: "bug" },
      component: {
        type: "string",
        description: "Service name, for example relaycontrol, relaycast, relayhistory, relayauth, relayfile, relayflows, 96bulls",
      },
      stepsToReproduce: { type: "string", maxLength: 4000 },
      expected: { type: "string", maxLength: 2000 },
      observed: { type: "string", maxLength: 2000 },
      supportBundle: {
        type: "object",
        description:
          "Optional output of helm-charts scripts/support/collect-support-bundle.py: {manifest, documents} " +
          "or a map of its JSON documents (versions.json, workload-status.json, ...).",
      },
      dryRun: { type: "boolean", default: false },
    },
  },
} as const;
