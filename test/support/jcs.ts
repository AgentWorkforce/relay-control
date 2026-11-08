/**
 * RFC 8785 (JSON Canonicalization Scheme) for the Desktop feed manifest's
 * value types only: objects, arrays, strings, safe integers, booleans and
 * null. Non-integer numbers are refused rather than serialised, because the
 * manifest has none and a client must not have to agree on ES number
 * formatting to verify it. Test support for the draft contract in
 * docs/desktop-feed.md; not used by the server.
 */
export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JcsError";
  }
}

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new JcsError(`not a safe integer: ${value}`);
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (typeof value === "string") return canonicalString(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new JcsError("not a plain object");
    const record = value as Record<string, unknown>;
    // Default string sort compares UTF-16 code units, as RFC 8785 section 3.2.3 requires.
    const keys = Object.keys(record).sort();
    return `{${keys.map((key) => `${canonicalString(key)}:${canonicalize(record[key])}`).join(",")}}`;
  }
  throw new JcsError(`unsupported type: ${typeof value}`);
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), "utf8");
}

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function canonicalString(value: string): string {
  // I-JSON (RFC 7493) forbids lone surrogates; JCS input must be I-JSON.
  if (LONE_SURROGATE.test(value)) throw new JcsError("lone surrogate in string");
  let out = '"';
  for (const char of value) {
    const code = char.codePointAt(0)!;
    if (char === '"') out += '\\"';
    else if (char === "\\") out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x09) out += "\\t";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0d) out += "\\r";
    else if (code < 0x20) out += `\\u${code.toString(16).padStart(4, "0")}`;
    else out += char;
  }
  return `${out}"`;
}
