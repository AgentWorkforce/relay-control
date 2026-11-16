import assert from "node:assert/strict";
import test from "node:test";
import { canonicalRelayhistoryOrigin } from "../src/relayhistory-origin.js";

test("customer History origins canonicalize to one database identity", () => {
  for (const variant of [
    "https://H.Example:443",
    "https://h.example:0443",
    "https://h.example.",
    " https://h.example/ ",
  ]) {
    assert.equal(canonicalRelayhistoryOrigin(variant), "https://h.example", variant);
  }
  assert.equal(canonicalRelayhistoryOrigin("https://bücher.example"), "https://xn--bcher-kva.example");
  assert.equal(canonicalRelayhistoryOrigin("https://[2001:0db8::1]:443"), "https://[2001:db8::1]");
  assert.equal(canonicalRelayhistoryOrigin("https://127.000.0.1"), "https://127.0.0.1");
  assert.equal(canonicalRelayhistoryOrigin("http://LOCALHOST:080"), "http://localhost");
});

test("customer History origins reject unsafe destinations and non-origins", () => {
  for (const value of [
    "http://history.customer.example",
    "ftp://history.customer.example",
    "https://user@history.customer.example",
    "https://history.customer.example/path",
    "not an origin",
  ]) {
    assert.equal(canonicalRelayhistoryOrigin(value), null, value);
  }
});
