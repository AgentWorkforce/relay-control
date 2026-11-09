// The canonicaliser lives in src since the Desktop feed was implemented; the
// contract tests keep importing it from here.
export { canonicalBytes, canonicalize, JcsError } from "../../src/desktop-feed/canonical.js";
