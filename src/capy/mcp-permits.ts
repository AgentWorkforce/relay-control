import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpContext } from "../mcp/context.js";
import { McpOAuthAccessRefused } from "../mcp/oauth/admission.js";
import { CapyBindingError } from "./bindings.js";

/** Optional OAuth send permits only. No binding creation, transfer or persona pin. */
export function registerCapyPermitTools(server: McpServer, context: McpContext): void {
  const run = async (work: () => Promise<unknown>) => {
    try {
      const oauth = context.oauth;
      if (!oauth || !context.capyPermits || oauth.access.principal.userId!==context.principal.userId ||
        oauth.access.principal.organizationId!==context.workspace.organizationId ||
        oauth.access.principal.workspaceId!==context.workspace.id ||
        context.principal.organizationId!==context.workspace.organizationId ||
        context.principal.workspaceId!==context.workspace.id) throw new McpOAuthAccessRefused();
      const data = await work();
      return { content:[{ type:"text" as const,text:JSON.stringify(data) }] };
    } catch (error) {
      return { isError:true,content:[{type:"text" as const,text:error instanceof CapyBindingError ? error.code
        : error instanceof McpOAuthAccessRefused ? error.message : "Capy reply permit is temporarily unavailable."}] };
    }
  };
  const inputSchema = { thread_id:z.string().regex(/^jam_[A-Za-z0-9]{6,64}$/) };
  const annotations = { readOnlyHint:false,destructiveHint:false,idempotentHint:true,openWorldHint:false };
  server.registerTool("bind_capy_thread",{
    description:"Allow this OAuth connection to send replies as an existing Capy thread binding owned by your connected key. Returns the existing binding; creates only a grant-specific send permit. Does not create or transfer a binding, change your approved persona, or grant inbox/channel/history access.",
    inputSchema,annotations,
  },({thread_id})=>run(()=>context.capyPermits!.bindGrant(context.oauth!,thread_id)));
  server.registerTool("unbind_capy_thread",{
    description:"Revoke only this OAuth connection's Capy reply permit for the selected thread. Native binding custody and inbound delivery remain active; other connections' permits are unchanged.",
    inputSchema,annotations:{...annotations,destructiveHint:true},
  },({thread_id})=>run(()=>context.capyPermits!.unbindGrant(context.oauth!,thread_id)));
}
