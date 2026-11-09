// The strict I-JSON parser lives in src since the Desktop feed was
// implemented; the contract tests keep importing it from here.
export { StrictJsonError, strictParse, type StrictJsonErrorKind } from "../../src/desktop-feed/strict-json.js";
