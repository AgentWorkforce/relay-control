export type McpCleanupCommand = {
  action: "list" | "retry" | "abandon";
  organizationId: string;
  workspaceId: string;
  intentId?: string;
  reason?: string;
};

export class McpCleanupCommandError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "McpCleanupCommandError";
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OPTIONS = new Set(["--organization", "--workspace", "--intent", "--reason"]);

/** Operator commands always name the tenant; there is no implicit install-wide target. */
export function parseMcpCleanupCommand(args: readonly string[]): McpCleanupCommand {
  const [action, ...rest] = args;
  if (action !== "list" && action !== "retry" && action !== "abandon") {
    throw new McpCleanupCommandError("Choose list, retry or abandon.");
  }
  const values = new Map<string, string>();
  for (let index = 0; index < rest.length; index += 2) {
    const option = rest[index]!;
    const value = rest[index + 1];
    if (!OPTIONS.has(option) || values.has(option) || !value || value.startsWith("--")) {
      throw new McpCleanupCommandError("Unknown, duplicate or incomplete option.");
    }
    values.set(option, value);
  }
  const id = (option: string, required: boolean): string | undefined => {
    const value = values.get(option);
    if (value === undefined && !required) return undefined;
    if (!value || !UUID.test(value)) throw new McpCleanupCommandError("Explicit organization, workspace and intent IDs must be UUIDs.");
    return value.toLowerCase();
  };
  const organizationId = id("--organization", true)!;
  const workspaceId = id("--workspace", true)!;
  const intentId = id("--intent", action !== "list");
  const reason = values.get("--reason")?.trim();
  if (action === "list" && values.has("--reason")) throw new McpCleanupCommandError("List does not take a reason.");
  if (action !== "list" && (!reason || reason.length > 200 || /[\u0000-\u001f\u007f]/u.test(reason))) {
    throw new McpCleanupCommandError("Mutating commands require a nonempty reason of at most 200 printable characters.");
  }
  return { action, organizationId, workspaceId, ...(intentId ? { intentId } : {}), ...(reason ? { reason } : {}) };
}
