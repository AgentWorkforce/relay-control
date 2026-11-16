import { createHash,createHmac } from "node:crypto";
import type { Client } from "pg";
import { decryptSecret,type EncryptionKeyring } from "../../src/crypto.js";
import { CredentialBlobStore,PostgresObjectBackend } from "../../src/admin/credential-blobs.js";
import type { Database } from "../../src/database.js";
import { describeAuthFile,type SubscriptionProvider } from "../../src/admin/subscription-logins.js";
import { canonicalProvider,cloudObjectKeys,type CloudObjectReader,type CredentialCopyReport } from "../cloud-import/credentials.js";
import { decryptCloudEnvelope } from "../cloud-import/importer.js";
import { credentialCopyQuery,MAPPING_REVISION,type ImportScope } from "../cloud-import/mapping.js";
import type { Finding } from "./verify.js";

export interface CredentialEvidence {
  report:CredentialCopyReport;
  reader:CloudObjectReader;
  targetBlobs:CredentialBlobStore;
}

/** CLI backend deliberately exposes local Postgres GETs only. */
export function readOnlyPostgresBlobs(target:Client,keyring:EncryptionKeyring):CredentialBlobStore {
  const db:Database = {
    query:async <T extends Record<string,unknown>>(sql:string,params:unknown[] = []) => ({rows:(await target.query(sql,params)).rows as T[]}),
    exec:async () => {throw new Error("read_only");},
    transaction:async () => {throw new Error("read_only");},close:async () => {},
  };
  return new CredentialBlobStore(new PostgresObjectBackend(db),keyring);
}
const hash = (value:string) => createHash("sha256").update(value).digest("hex");
const fingerprint = (provider:string,type:string,secret:string,keyring:EncryptionKeyring) =>
  createHmac("sha256",keyring.active.key).update(`selfhost-coding-agent-credential\0${provider}\0${type}\0${secret}`).digest("hex");
const naturalKey = (workspace:string,provider:string,type:string,identity:string) =>
  hash(JSON.stringify([workspace,provider,type,identity]));
const digestKeys = (keys:Iterable<string>) => hash(JSON.stringify([...keys].sort()));

/** Read-only selection cardinality: model and sandbox are distinct selectors.
 * An OAuth-login-only group has sandbox access, not model-call access.
 */
export async function credentialSelections(target:Client,scope:ImportScope):Promise<Finding[]> {
  const groups = await target.query(`SELECT c.workspace_id::text,c.model_provider,
    count(*) FILTER(WHERE c.auth_type <> 'provider_oauth')::int AS model_eligible,
    count(*) FILTER(WHERE c.auth_type IN ('oauth_token','provider_oauth'))::int AS harness_eligible,
    count(*) FILTER(WHERE c.is_active)::int AS model_active,
    count(*) FILTER(WHERE c.harness_active)::int AS harness_active
    FROM public.coding_agent_credentials c JOIN public.workspaces w ON w.id=c.workspace_id
    WHERE $1::uuid[] IS NULL OR w.organization_id=ANY($1::uuid[])
    GROUP BY c.workspace_id,c.model_provider ORDER BY c.workspace_id,c.model_provider`,[scope.orgIds]);
  return groups.rows.map((group) => ({kind:"credential_selection",name:`${group.workspace_id}:${group.model_provider}`,
    ok:group.model_active === (group.model_eligible > 0 ? 1 : 0)
      && group.harness_active === (group.harness_eligible > 0 ? 1 : 0),detail:group}));
}

type Expected = {org:string;workspace:string;provider:string;authType:string;identity:string;fingerprint:string;contentHash:string};

/** Caller owns frozen read-only source/target snapshots. No store methods that
 * mint, rotate, refresh or mutate credentials are called. Reports retain only
 * counts and hashes; plaintext, fingerprints and account identities stay out.
 */
export async function credentialCopyFindings(source:Client,target:Client,scope:ImportScope,
  evidence:CredentialEvidence,keyring:EncryptionKeyring,cloudKeyHex:string):Promise<Finding[]> {
  const expected = new Map<string,Expected>();
  const sourceIds = new Set<string>();
  const expectedOutcomes:Record<string,number> = {};
  const {report} = evidence;
  let candidates = 0;
  let sourceFailures = 0;
  let unresolvedSourceSkips = 0;
  let rowOutcomesMatch = true;
  await source.query(`DECLARE credential_copy_cursor NO SCROLL CURSOR FOR ${credentialCopyQuery(scope)}`);
  try {for (;;) {
    const batch = await source.query("FETCH FORWARD 250 FROM credential_copy_cursor");
    if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (++candidates > 10000) throw new Error("Credential verification exceeds the bounded cohort size");
      sourceIds.add(row.id);
      const outcome = report.rows?.[row.id];
      if (typeof outcome === "string") expectedOutcomes[outcome] = (expectedOutcomes[outcome] ?? 0)+1;
      if (row.skip_reason) {
        rowOutcomesMatch &&= outcome === `skipped:${row.skip_reason}`;
        if (!["workspace_not_imported","user_not_imported"].includes(row.skip_reason)) unresolvedSourceSkips++;
        continue;
      }
      let plaintext:string|undefined;
      try {
        for (const key of cloudObjectKeys(row as Parameters<typeof cloudObjectKeys>[0])) {
          const body = await evidence.reader.get(key);
          if (body === null) continue;
          plaintext = decryptCloudEnvelope(JSON.parse(body),cloudKeyHex); break;
        }
        if (plaintext === undefined) {sourceFailures++;rowOutcomesMatch &&= outcome === "object_missing";continue;}
        const provider = canonicalProvider(row.model_provider);
        let identity:string;
        let content:string;
        let fp:string;
        if (row.auth_type === "provider_oauth") {
          const described = describeAuthFile(provider as SubscriptionProvider,plaintext);
          identity = `account:${described.accountId}`;
          content = plaintext;
          fp = fingerprint(provider,row.auth_type,described.refreshToken,keyring);
        } else {
          const payload = JSON.parse(plaintext);
          const value = row.auth_type === "byo_api_key" ? payload.key : payload.token;
          if (typeof value !== "string" || !value.trim()) throw new Error("invalid_secret_payload");
          content = value.trim();
          fp = fingerprint(provider,row.auth_type,content,keyring);
          identity = row.auth_type === "oauth_token" && row.account_email?.trim()
            ? `account:${row.account_email.trim().toLowerCase()}` : `fingerprint:${fp}`;
        }
        // Last source row wins when Control replaces a setup token or login
        // for the same account. Only hashes, never plaintext, are retained.
        expected.set(naturalKey(row.workspace_id,provider,row.auth_type,identity),{
          org:row.organization_id,workspace:row.workspace_id,provider,authType:row.auth_type,identity,
          fingerprint:fp,contentHash:hash(content),
        });
        rowOutcomesMatch &&= outcome === "copied" || outcome === "already_present";
      } catch {sourceFailures++;rowOutcomesMatch = false;}
    }
  }} finally {await source.query("CLOSE credential_copy_cursor");}
  const reportedIds = Object.keys(report.rows ?? {});
  const totals = (values:Record<string,number>) => JSON.stringify(Object.entries(values).sort(([a],[b]) => a.localeCompare(b)));
  const findings:Finding[] = [{kind:"credential_copy_ledger",name:"run",
    ok:report.version === 1 && report.mappingRevision === MAPPING_REVISION && report.mode === "apply" && report.ok
      && report.candidates === candidates && reportedIds.length === sourceIds.size
      && reportedIds.every((id) => sourceIds.has(id)) && rowOutcomesMatch
      && totals(report.outcomes) === totals(expectedOutcomes),
    detail:{candidates,sourceFailures,unresolvedSourceSkips,reportedCandidates:report.candidates}}];
  const seen = new Set<string>();
  let duplicateKeys = 0;
  let contentFailures = 0;
  let extra = 0;
  const targetExecutor = {
    query:async <T extends Record<string,unknown>>(sql:string,params:unknown[] = []) => ({rows:(await target.query(sql,params)).rows as T[]}),
    exec:async (sql:string) => {await target.query(sql);},
  };
  await target.query(`DECLARE credential_target_cursor NO SCROLL CURSOR FOR
    SELECT c.* FROM public.coding_agent_credentials c JOIN public.workspaces w ON w.id=c.workspace_id
    WHERE c.auth_type <> 'relay_managed' AND ($1::uuid[] IS NULL OR w.organization_id=ANY($1::uuid[]))`,[scope.orgIds]);
  try {for (;;) {
    const batch = await target.query("FETCH FORWARD 250 FROM credential_target_cursor");
    if (!batch.rows.length) break;
    for (const row of batch.rows) {
      if (seen.size > 10000) throw new Error("Credential verification exceeds the bounded cohort size");
      const identity = row.auth_type === "provider_oauth" ? `account:${row.provider_account_id}`
        : row.auth_type === "oauth_token" && row.account_email?.trim()
          ? `account:${row.account_email.trim().toLowerCase()}` : `fingerprint:${row.key_fingerprint}`;
      const key = naturalKey(row.workspace_id,row.model_provider,row.auth_type,identity);
      if (seen.has(key)) duplicateKeys++;
      seen.add(key);
      const wanted = expected.get(key);
      if (!wanted) {extra++;continue;}
      try {
        if (row.auth_type === "provider_oauth" && row.blob_backend !== evidence.targetBlobs.kind) throw new Error("blob_backend_mismatch");
        const content = row.auth_type === "provider_oauth"
          ? await evidence.targetBlobs.read(row.blob_location,row.id,Number(row.blob_version),targetExecutor)
          : decryptSecret(row.secret_ciphertext,keyring);
        if (row.organization_id !== wanted.org || row.status !== "connected"
          || row.key_fingerprint !== wanted.fingerprint || hash(content) !== wanted.contentHash) contentFailures++;
      } catch {contentFailures++;}
    }
  }} finally {await target.query("CLOSE credential_target_cursor");}
  const missing = [...expected.keys()].filter((key) => !seen.has(key)).length;
  findings.push({kind:"credential_natural_keys",name:"coding_agent_credentials",
    ok:!sourceFailures && !unresolvedSourceSkips && !duplicateKeys && !contentFailures && !extra && !missing,
    detail:{expected:expected.size,target:seen.size,missing,extra,duplicateKeys,contentFailures,
      sourceFailures,unresolvedSourceSkips,sourceChecksum:digestKeys(expected.keys()),targetChecksum:digestKeys(seen)}});
  return findings;
}
