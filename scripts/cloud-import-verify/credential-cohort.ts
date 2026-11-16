import type { SourceSelection } from "./credential-selection.js";

export type CredentialCandidate={selection:SourceSelection;authType:string};

/** .21's producer groups logins by independently decrypted account identity,
 * chooses freshest then lowest UUID, and carries selection from all duplicates.
 * API keys/setup tokens retain their own row semantics. */
export function deduplicatesLogins(revision:string):boolean {
  const match=/^cloud-identity-2026-11-16\.(\d+)$/.exec(revision);
  return match !== null && Number(match[1]) >= 21;
}
export function credentialLoginCohort<T extends CredentialCandidate>(rows:readonly T[],deduplicate:boolean):{
  selected:T[];duplicates:Set<string>;
} {
  if (!deduplicate) return {selected:[...rows],duplicates:new Set()};
  const groups=new Map<string,T[]>();
  for (const row of rows) if (row.authType === "provider_oauth") {
    const group=groups.get(row.selection.key) ?? [];group.push(row);groups.set(row.selection.key,group);
  }
  const duplicates=new Set<string>();
  const winners=new Map<string,T>();
  for (const [key,group] of groups) {
    const winner=[...group].sort((a,b) => b.selection.updated-a.selection.updated
      || a.selection.id.localeCompare(b.selection.id))[0]!;
    for (const row of group) if (row !== winner) duplicates.add(row.selection.id);
    winners.set(key,{...winner,selection:{...winner.selection,
      active:group.some((row) => row.selection.active),harness:group.some((row) => row.selection.harness)}});
  }
  return {selected:rows.flatMap((row) => row.authType !== "provider_oauth" ? [row]
    : duplicates.has(row.selection.id) ? [] : [winners.get(row.selection.key)!]),duplicates};
}
