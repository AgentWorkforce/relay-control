import type { Database, SqlExecutor } from "../database.js";
import { recordAudit, type AuditActor } from "../admin/audit.js";
import { rulesTextProblem, type AgentRulesAudience } from "./bundle.js";

export class AgentRulesInputError extends Error {}

export type Overlay = { version: number; text: string; updatedAt: string };
const CACHE_MS = 60_000;

/** Organization overlays, newest version active. Reads are cached for 60s in-process and invalidated on write. */
export class AgentRulesOverlays {
  private cache = new Map<string, { at: number; value: Overlay | null }>();
  constructor(private readonly database: Database, private readonly now: () => Date = () => new Date()) {}

  async read(organizationId: string, audience: AgentRulesAudience, executor: SqlExecutor = this.database): Promise<Overlay | null> {
    const key = `${organizationId}:${audience}`;
    const hit = this.cache.get(key);
    if (hit && this.now().getTime() - hit.at < CACHE_MS) return hit.value;
    const row = (await executor.query<{ version: number; text: string; updated_at: Date | string }>(
      `SELECT version,text,updated_at FROM agent_rules_overlays WHERE organization_id=$1 AND audience=$2
       ORDER BY version DESC LIMIT 1`, [organizationId, audience])).rows[0];
    const value = row && row.text.trim() ? { version: Number(row.version), text: row.text, updatedAt: new Date(row.updated_at).toISOString() } : null;
    this.cache.set(key, { at: this.now().getTime(), value });
    return value;
  }

  /** Appends a new version (an empty text clears the overlay) and audits it. */
  async write(input: { organizationId: string; audience: AgentRulesAudience; text: string; actor: AuditActor }): Promise<{ version: number; cleared: boolean }> {
    const text = input.text.trim();
    const problem = text ? rulesTextProblem(text) : null;
    if (problem) throw new AgentRulesInputError(problem);
    const result = await this.database.transaction(async tx => {
      await tx.query("SELECT pg_advisory_xact_lock(hashtext($1))", [`agent_rules:${input.organizationId}:${input.audience}`]);
      const next = Number((await tx.query<{ next: number }>(`SELECT COALESCE(MAX(version),0)+1 AS next FROM agent_rules_overlays
        WHERE organization_id=$1 AND audience=$2`, [input.organizationId, input.audience])).rows[0]!.next);
      await tx.query(`INSERT INTO agent_rules_overlays(organization_id,audience,version,text,updated_by,updated_at)
        VALUES ($1,$2,$3,$4,$5,$6)`, [input.organizationId, input.audience, next, text,
        input.actor.kind === "user" ? input.actor.userId : null, this.now()]);
      await recordAudit(tx, { organizationId: input.organizationId, actor: input.actor,
        action: text ? "agent_rules.overlay_set" : "agent_rules.overlay_cleared", target: `${input.audience} v${next}` });
      return { version: next, cleared: !text };
    });
    this.cache.delete(`${input.organizationId}:${input.audience}`);
    return result;
  }
}
