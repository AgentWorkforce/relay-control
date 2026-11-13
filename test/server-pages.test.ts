import assert from "node:assert/strict";
import test from "node:test";
import { desktopConsentDeniedPage, desktopConsentPage, desktopWorkspacePickerPage } from "../src/auth/desktop-login.js";
import { page } from "../src/identity/pages.js";

const params = new URLSearchParams({ client: "desktop", state: "s1", desktop_host_name: "example-laptop" });

test("Desktop consent matches Cloud's page and keeps its form fields", () => {
  const html = desktopConsentPage({ action: "/cloud/api/v1/cli/login", params, hostName: "<laptop>", workspaceName: "Example Corp", consentToken: "tok\"en" });
  assert.match(html, /<title>Authorize a device · Agent Relay<\/title>/);
  assert.match(html, /<p>Requesting app or device<\/p><h1>Agent Relay Desktop on &lt;laptop&gt;<\/h1>/);
  assert.match(html, /to access your workspace <strong>Example Corp<\/strong>\./);
  assert.match(html, /<button type="submit" name="decision" value="approve">Approve<\/button>/);
  assert.match(html, /<button type="submit" name="decision" value="deny">Deny<\/button>/);
  assert.match(html, /<input type="hidden" name="consent_token" value="tok&quot;en">/);
  assert.match(html, /<input type="hidden" name="state" value="s1">/);
});

test("Desktop denied and workspace picker match Cloud's pages and escape names", () => {
  assert.match(desktopConsentDeniedPage(), /<h1>Device denied<\/h1>/);
  const picker = desktopWorkspacePickerPage({ action: "/cloud/api/v1/cli/login", params, workspaces: [{ id: "w1", name: "<Default>", organizationName: "Example Corp" }, { id: "w2", name: "Solo", organizationName: "Solo" }] });
  assert.match(picker, /<form method="get" action="\/cloud\/api\/v1\/cli\/login">/);
  assert.match(picker, /<input type="hidden" name="state" value="s1">/);
  assert.match(picker, /<option value="w1">Example Corp \/ &lt;Default&gt;<\/option><option value="w2">Solo<\/option>/);
});

test("a nonce marks both the inline style and the script", () => {
  const html = page("T", "<h1>T</h1>", "void 0", "", "n0nce");
  assert.match(html, /<style nonce="n0nce">/);
  assert.match(html, /<script nonce="n0nce">void 0<\/script>/);
  assert.doesNotMatch(page("T", "<h1>T</h1>"), /nonce=/);
});
