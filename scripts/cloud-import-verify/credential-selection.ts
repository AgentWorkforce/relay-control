import type { Finding } from "./verify.js";

export type SourceSelection={id:string;key:string;group:string;active:boolean;harness:boolean;updated:number};
export type TargetSelection={group:string;active:boolean;harness:boolean};
type SelectionSummary={groups:number;active:number;harness:number;activeDemoted:number;harnessDemoted:number;selectionConflicts:number};

/** Revision .25 changed the producer's selection cohort. Historical reports
 * retain their original semantics; the enclosing ledger check still requires
 * an exact current MAPPING_REVISION, never a caller-selected policy. */
export function writtenOnlySelection(revision:string):boolean {
  const match=/^cloud-identity-2026-11-16\.(\d+)$/.exec(revision);
  return match !== null && Number(match[1]) >= 25;
}

export function credentialCloudSelection(input:{revision:string;entries:SourceSelection[];outcomes:Record<string,unknown>;
  flags:Map<string,TargetSelection>;nativeFlags:Map<string,TargetSelection>;baseline:Map<string,TargetSelection>;
  allFlags:TargetSelection[];unchangedKeys:Set<string>;reported:SelectionSummary|undefined}):Finding {
  const writtenOnly=writtenOnlySelection(input.revision);
  const entries=input.entries.filter((entry) => !writtenOnly
    || input.outcomes[entry.id] === "copied" || input.outcomes[entry.id] === "updated");
  const writtenKeys=new Set(entries.map((entry) => entry.key));
  const summary:SelectionSummary={groups:0,active:0,harness:0,activeDemoted:0,harnessDemoted:0,selectionConflicts:0};
  let selectionMismatches=0,untouchedWithoutBaseline=0;
  const groups=new Map<string,SourceSelection[]>();
  for (const entry of entries) {const group=groups.get(entry.group) ?? [];group.push(entry);groups.set(entry.group,group);}
  const groupCounts=new Map<string,{active:number;harness:number}>();
  for (const row of input.allFlags) {
    const count=groupCounts.get(row.group) ?? {active:0,harness:0};
    count.active+=Number(row.active);count.harness+=Number(row.harness);groupCounts.set(row.group,count);
  }
  for (const [group,rows] of groups) {
    summary.groups++;
    const keys=new Set(rows.map((entry) => entry.key));
    const flags=[...input.flags].filter(([key]) => keys.has(key));
    for (const column of ["active","harness"] as const) {
      const candidates=rows.filter((entry) => entry[column]);
      const chosen=[...candidates].sort((a,b) => b.updated-a.updated || a.id.localeCompare(b.id))[0];
      const selected=flags.filter(([,entry]) => entry[column]);
      if (chosen) {
        summary[column]++;
        const demoted=Math.max(0,new Set(candidates.map((entry) => entry.key)).size-1);
        if (column === "active") summary.activeDemoted+=demoted;else summary.harnessDemoted+=demoted;
        if (selected.length !== 1 || selected[0]![0] !== chosen.key || groupCounts.get(group)?.[column] !== 1) selectionMismatches++;
      } else if (selected.length) {
        if (column === "active") summary.selectionConflicts++;else selectionMismatches++;
      }
    }
    if (flags.length !== keys.size) selectionMismatches++;
  }
  // A written winner may legitimately demote other rows in its group. With
  // no winner, untouched rows must preserve their prior Control flags. A
  // complete unchanged convergence tuple is also independent prior evidence.
  const untouched=new Map(input.baseline);
  if (writtenOnly) for (const entry of input.entries) {
    if (!writtenKeys.has(entry.key) && !untouched.has(entry.key)) {
      const current=input.flags.get(entry.key);
      if (!current) {selectionMismatches++;continue;}
      const noPriorNeeded=(["active","harness"] as const).every((column) =>
        groups.get(entry.group)?.some((candidate) => candidate[column]) && !current[column]);
      if (!input.unchangedKeys.has(entry.key) && !noPriorNeeded) untouchedWithoutBaseline++;
    }
  }
  for (const [key,prior] of untouched) {
    if (writtenKeys.has(key) || (!writtenOnly && input.flags.has(key))) continue;
    // A dedicated pre-rerun checkpoint is newer evidence than the original
    // pre-first-copy baseline, whose flags may have been legitimately demoted
    // by that first copy. Full tuple equality proves the rerun preserved them.
    if (writtenOnly && input.unchangedKeys.has(key)) continue;
    const current=input.flags.get(key) ?? input.nativeFlags.get(key);
    if (!current) {selectionMismatches++;continue;}
    for (const column of ["active","harness"] as const) {
      const chosen=groups.get(prior.group)?.some((entry) => entry[column]);
      if (current[column] !== (chosen ? false : prior[column])) selectionMismatches++;
    }
  }
  const reportMatches=input.reported === undefined ? groups.size === 0
    : Object.entries(summary).every(([key,value]) => input.reported![key as keyof SelectionSummary] === value);
  return {kind:"credential_cloud_selection",name:"coding_agent_credentials",
    ok:reportMatches && !selectionMismatches && !untouchedWithoutBaseline && !summary.selectionConflicts,
    detail:{...summary,selectionMismatches,untouchedWithoutBaseline,reportMatches,
      policy:writtenOnly ? "written_rows" : "all_matching_rows",selectionKeys:writtenKeys.size,
      untouchedKeys:writtenOnly ? new Set(input.entries.filter((entry) => !writtenKeys.has(entry.key)).map((entry) => entry.key)).size : 0}};
}
