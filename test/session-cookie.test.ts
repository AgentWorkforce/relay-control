import assert from "node:assert/strict";
import test from "node:test";
import { controlSessionToken } from "../src/auth/session-cookie.js";

test("Control session cookie wins when Cloud's same-name cookie is first", () => {
  assert.equal(
    controlSessionToken("agent_relay_session=cloud-session; agent_relay_session=sh_at_control-session"),
    "sh_at_control-session",
  );
});

test("Control session cookie wins when browser order is reversed", () => {
  assert.equal(
    controlSessionToken("agent_relay_session=sh_at_control-session; agent_relay_session=cloud-session"),
    "sh_at_control-session",
  );
});

test("Cloud-only and malformed cookies are not accepted as Control sessions", () => {
  assert.equal(controlSessionToken("agent_relay_session=cloud-session"), null);
  assert.equal(
    controlSessionToken("agent_relay_session=%ZZ; agent_relay_session=sh_at_valid"),
    "sh_at_valid",
  );
});
