import { APP_BASE_PATH } from "../mcp/oauth/protocol.js";

/** Where an account was created (users.signup_source, migration 0068). */
export type SignupSource = "teams" | "flows" | "desktop" | "mcp";

const MCP_AUTHORIZE = `${APP_BASE_PATH}/oauth/authorize`;

/**
 * The source a sign-in's post-login return path names, or null. Control has
 * one attributable creation path of its own: an MCP connector (ChatGPT's
 * Agent Relay app or any MCP OAuth client) sends a new person through
 * sign-in and back to OAuth consent. Only same-origin relative paths count.
 */
export function signupSourceFromNext(next: string | null | undefined): SignupSource | null {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return null;
  try {
    const origin = "https://control.invalid";
    const destination = new URL(next, origin);
    if (destination.origin !== origin) return null;
    // The MCP authorize route matches with trailing slashes stripped, so
    // /cloud/oauth/authorize/ is the same consent page.
    return destination.pathname.replace(/\/+$/, "") === MCP_AUTHORIZE ? "mcp" : null;
  } catch {
    return null;
  }
}
