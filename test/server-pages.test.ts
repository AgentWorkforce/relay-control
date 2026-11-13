import assert from "node:assert/strict";
import test from "node:test";
import { desktopConsentDeniedPage, desktopConsentPage, desktopWorkspacePickerPage } from "../src/auth/desktop-login.js";
import { page } from "../src/identity/pages.js";

const params = new URLSearchParams({ client: "desktop", state: "s1", desktop_host_name: "example-laptop" });

test("Desktop consent uses the branded page and keeps its form fields", () => {
  const html = desktopConsentPage({ action: "/cloud/api/v1/cli/login", params, hostName: "<laptop>", workspaceName: "Example Corp", consentToken: "tok\"en" });
  assert.match(html, /<header class="brand">/);
  assert.match(html, /<div class="card">/);
  assert.match(html, /<button class="btn" type="submit" name="decision" value="approve">Approve<\/button>/);
  assert.match(html, /<button class="btn secondary" type="submit" name="decision" value="deny">Deny<\/button>/);
  assert.match(html, /<input type="hidden" name="consent_token" value="tok&quot;en">/);
  assert.match(html, /<input type="hidden" name="state" value="s1">/);
  assert.match(html, /<strong>&lt;laptop&gt;<\/strong>/);
});

test("Desktop denied and workspace picker pages use the branded page and escape names", () => {
  assert.match(desktopConsentDeniedPage(), /<header class="brand">[\s\S]*<h1>Sign-in denied<\/h1>/);
  const picker = desktopWorkspacePickerPage({ action: "/cloud/api/v1/cli/login", params, workspaces: [{ id: "w1", name: "<Default>", organizationName: "Example Corp" }] });
  assert.match(picker, /<header class="brand">/);
  assert.match(picker, /<a class="choice" href="\/cloud\/api\/v1\/cli\/login\?client=desktop&amp;state=s1&amp;desktop_host_name=example-laptop&amp;workspace=w1">&lt;Default&gt; <span class="muted">Example Corp<\/span><\/a>/);
});

test("a nonce marks both the inline style and the script", () => {
  const html = page("T", "<h1>T</h1>", "void 0", "", "n0nce");
  assert.match(html, /<style nonce="n0nce">/);
  assert.match(html, /<script nonce="n0nce">void 0<\/script>/);
  assert.doesNotMatch(page("T", "<h1>T</h1>"), /nonce=/);
});
