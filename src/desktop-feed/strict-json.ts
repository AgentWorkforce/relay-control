/**
 * Strict I-JSON (RFC 7493) parser for the Desktop feed envelope. RFC 8785
 * section 3.1 requires JCS input to be I-JSON, but JSON.parse keeps the last
 * of duplicate member names, so a canonicaliser fed its result cannot see the
 * duplicate. This parser follows the RFC 8259 grammar, returns the same
 * values as JSON.parse for valid input, and throws StrictJsonError on a
 * duplicate member name (compared after escape decoding), on a lone
 * surrogate, and on anything outside RFC 8259 (including a leading BOM).
 * Non-integer numbers parse as JSON.parse would; canonical.ts refuses them
 * later. Used by the import route (src/desktop-feed/routes.ts) and the
 * contract tests (test/support/strict-json.ts re-exports it).
 */
export type StrictJsonErrorKind = "syntax" | "duplicate_name" | "lone_surrogate";

export class StrictJsonError extends Error {
  constructor(
    readonly kind: StrictJsonErrorKind,
    message: string,
    readonly position: number,
  ) {
    super(`${message} at ${position}`);
    this.name = "StrictJsonError";
  }
}

export function strictParse(text: string): unknown {
  const parser = new Parser(text);
  parser.whitespace();
  const value = parser.value();
  parser.whitespace();
  if (parser.pos !== text.length) parser.fail("syntax", "trailing characters");
  return value;
}

const ESCAPES: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

class Parser {
  pos = 0;
  constructor(private readonly text: string) {}

  fail(kind: StrictJsonErrorKind, message: string, at = this.pos): never {
    throw new StrictJsonError(kind, message, at);
  }

  /** RFC 8259 whitespace: space, tab, line feed, carriage return. Nothing else, not even U+FEFF. */
  whitespace(): void {
    for (;;) {
      const char = this.text[this.pos];
      if (char !== " " && char !== "\t" && char !== "\n" && char !== "\r") return;
      this.pos++;
    }
  }

  expect(char: string): void {
    if (this.text[this.pos] !== char) this.fail("syntax", `expected ${JSON.stringify(char)}`);
    this.pos++;
  }

  literal(word: string, value: unknown): unknown {
    if (!this.text.startsWith(word, this.pos)) this.fail("syntax", "unexpected token");
    this.pos += word.length;
    return value;
  }

  value(): unknown {
    const char = this.text[this.pos];
    if (char === "{") return this.object();
    if (char === "[") return this.array();
    if (char === '"') return this.string();
    if (char === "t") return this.literal("true", true);
    if (char === "f") return this.literal("false", false);
    if (char === "n") return this.literal("null", null);
    if (char === "-" || isDigit(char)) return this.number();
    return this.fail("syntax", char === undefined ? "unexpected end of input" : "unexpected token");
  }

  object(): Record<string, unknown> {
    this.expect("{");
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.whitespace();
    if (this.text[this.pos] === "}") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.whitespace();
      const at = this.pos;
      if (this.text[at] !== '"') this.fail("syntax", "expected member name");
      const name = this.string();
      if (seen.has(name)) this.fail("duplicate_name", `duplicate member name ${JSON.stringify(name)}`, at);
      seen.add(name);
      this.whitespace();
      this.expect(":");
      this.whitespace();
      // defineProperty, so a "__proto__" member is an own property as with JSON.parse.
      Object.defineProperty(out, name, { value: this.value(), enumerable: true, writable: true, configurable: true });
      this.whitespace();
      if (this.text[this.pos] === "}") {
        this.pos++;
        return out;
      }
      this.expect(",");
    }
  }

  array(): unknown[] {
    this.expect("[");
    const out: unknown[] = [];
    this.whitespace();
    if (this.text[this.pos] === "]") {
      this.pos++;
      return out;
    }
    for (;;) {
      this.whitespace();
      out.push(this.value());
      this.whitespace();
      if (this.text[this.pos] === "]") {
        this.pos++;
        return out;
      }
      this.expect(",");
    }
  }

  string(): string {
    const start = this.pos;
    this.expect('"');
    let out = "";
    for (;;) {
      const char = this.text[this.pos];
      if (char === undefined) this.fail("syntax", "unterminated string");
      if (char === '"') break;
      if (char.charCodeAt(0) < 0x20) this.fail("syntax", "unescaped control character");
      if (char !== "\\") {
        out += char;
        this.pos++;
        continue;
      }
      const escape = this.text[this.pos + 1];
      if (escape === "u") {
        const hex = this.text.slice(this.pos + 2, this.pos + 6);
        if (hex.length !== 4 || ![...hex].every(isHexDigit)) this.fail("syntax", "bad \\u escape");
        out += String.fromCharCode(parseInt(hex, 16));
        this.pos += 6;
      } else if (escape !== undefined && Object.hasOwn(ESCAPES, escape)) {
        out += ESCAPES[escape];
        this.pos += 2;
      } else {
        this.fail("syntax", "bad escape");
      }
    }
    this.pos++;
    // I-JSON: after decoding, every surrogate code unit must be part of a pair.
    for (let i = 0; i < out.length; i++) {
      const unit = out.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = out.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) i++;
        else this.fail("lone_surrogate", "lone surrogate in string", start);
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        this.fail("lone_surrogate", "lone surrogate in string", start);
      }
    }
    return out;
  }

  /** number = [ "-" ] int [ frac ] [ exp ]; int = "0" / digit1-9 *DIGIT. */
  number(): number {
    const start = this.pos;
    if (this.text[this.pos] === "-") this.pos++;
    if (this.text[this.pos] === "0") this.pos++;
    else if (isDigit(this.text[this.pos])) this.digits();
    else this.fail("syntax", "bad number");
    if (this.text[this.pos] === ".") {
      this.pos++;
      if (!isDigit(this.text[this.pos])) this.fail("syntax", "bad fraction");
      this.digits();
    }
    if (this.text[this.pos] === "e" || this.text[this.pos] === "E") {
      this.pos++;
      if (this.text[this.pos] === "+" || this.text[this.pos] === "-") this.pos++;
      if (!isDigit(this.text[this.pos])) this.fail("syntax", "bad exponent");
      this.digits();
    }
    return Number(this.text.slice(start, this.pos));
  }

  digits(): void {
    while (isDigit(this.text[this.pos])) this.pos++;
  }
}

function isDigit(char: string | undefined): boolean {
  return char !== undefined && char >= "0" && char <= "9";
}

function isHexDigit(char: string): boolean {
  return isDigit(char) || (char >= "a" && char <= "f") || (char >= "A" && char <= "F");
}
