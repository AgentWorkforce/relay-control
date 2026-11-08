/** Shared by the SQL store and consent handlers; preserve typed HTTP mapping. */
export class McpOAuthContinuationError extends Error {}
export class McpOAuthAgentNameTakenError extends Error {
  readonly status = 409;
  readonly code = "agent_name_taken";
  constructor() { super("That name is already in use. Choose another name."); }
}
