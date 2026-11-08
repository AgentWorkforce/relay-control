const REDACTED = "[REDACTED]";

type Replacement =
  | string
  | ((substring: string, ...groups: string[]) => string);

const isWordChar = (char: string | undefined) =>
  !!char && /[A-Za-z0-9_]/.test(char);

/**
 * Redacts every `header.payload.signature` JWT inside one dot-joined token run: the
 * header starts with `eyJ` at a word boundary (8+ chars after it), the payload is a
 * whole segment starting `eyJ` (8+ chars after it), and the signature a whole segment
 * of 16+ chars.
 */
function redactJwtsInRun(run: string): string {
  if (!run.includes(".eyJ")) return run;
  const segments = run.split(".");
  const out: string[] = [];
  for (let i = 0; i < segments.length; i += 1) {
    const header = segments[i] as string;
    const payload = segments[i + 1];
    const signature = segments[i + 2];
    if (
      payload &&
      signature &&
      payload.startsWith("eyJ") &&
      payload.length >= 11 &&
      signature.length >= 16
    ) {
      let start = header.indexOf("eyJ");
      while (
        start !== -1 &&
        (isWordChar(header[start - 1]) || header.length - start < 11)
      ) {
        start = isWordChar(header[start - 1])
          ? header.indexOf("eyJ", start + 1)
          : -1;
      }
      if (start !== -1) {
        out.push(header.slice(0, start) + REDACTED);
        i += 2;
        continue;
      }
    }
    out.push(header);
  }
  return out.join(".");
}

/**
 * Whether a key names a secret, for the quoted key/value rule. Compound names
 * (`api_key`, `accessKey`, `SecretAccessKey`, `client-secret`, `sessiontoken`…) count
 * wherever they end the key. Single words (`password`, `token`, `auth`…) count only as a
 * whole word at the end of the key: at its start, after a non-letter (`db_password`,
 * `x-auth-token`, `cf.token`) or at a camelCase hump (`githubToken`), so `oauth`,
 * `author` and `tokens` are not secret names. A bare `key` is not one either: quoted
 * `"key"` is everywhere in tool output (S3 object keys, keyboard events, cache keys).
 */
const SECRET_KEY_COMPOUND =
  /(?:api|access|private|secret|auth|signing|encryption|master)[_ -]?key$|client[_ -]?secret$|(?:session|access|refresh|auth|id|bot|bearer|api)[_ -]?token$/i;
const SECRET_KEY_WORD =
  /(?:password|passwd|passphrase|secret|token|auth|authorization|credentials?|bearer)$/i;

export function isSecretKeyName(name: string): boolean {
  if (SECRET_KEY_COMPOUND.test(name)) return true;
  const m = SECRET_KEY_WORD.exec(name);
  if (!m) return false;
  if (m.index === 0) return true;
  const prev = name[m.index - 1] as string;
  if (!/[A-Za-z]/.test(prev)) return true;
  return /[a-z]/.test(prev) && /[A-Z]/.test(name[m.index] as string);
}

/**
 * A quoted key at any JSON escaping depth (`"k"`, `\"k\"`, `\\\"k\\\"`, `'k'`, `` `k` ``),
 * then `:`, `=` or `=>` with optional whitespace. The leading lookbehind starts the
 * match at the beginning of a backslash run, and every quantifier is bounded, so each
 * start position is O(1) and the scan is linear.
 */
const QUOTED_KEY =
  /(?<!\\)(\\{0,16})(["'`])([A-Za-z0-9_. -]{1,64})\1\2([ \t]{0,16}(?:=>|[:=])[ \t]{0,16})/g;

/** Longest quoted value the quoted key/value rule looks through for its closing quote. */
const MAX_QUOTED_VALUE = 4096;

/** JSON literals and numbers after a quoted secret key are not secrets (`"max_token": 512`). */
const NON_SECRET_BARE =
  /^(?:true|false|null|undefined|none|-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)$/i;

/** Values the quoted key/value rule keeps: already redacted, or a 1Password reference. */
const keepQuotedValue = (value: string) =>
  value === REDACTED || value.startsWith("op://");

/** Number of backslashes immediately before `at`. */
function backslashesBefore(text: string, at: number): number {
  let n = 0;
  while (at - n - 1 >= 0 && text[at - n - 1] === "\\") n += 1;
  return n;
}

/**
 * Redact the value of every quoted secret key, keeping the key, the separator and the
 * value's quotes: `"password": "x"`, `\"password\": \"x\"` (a JSON document inside a
 * JSON string, such as a tool result), deeper escapings, single-quoted and backtick
 * forms, and an unquoted value after a quoted key (`'token' => abc`). The value ends at
 * the matching closing quote: a quote escaped once more than the opening one (an inner
 * quote) does not end it, and nor does one preceded by an escaped backslash. A value
 * with no closing quote on its line is redacted to the next whitespace. JSON literals and
 * numbers are kept, as are values already redacted and `op://` references.
 */
function redactQuotedSecretValues(text: string): string {
  if (!/[:=]/.test(text)) return text;
  let out = "";
  let last = 0;
  // Per quote kind (quote character and backslash count), the span a scan already
  // walked without finding a closing quote. A later value of the same kind that starts
  // inside it cannot close there either, so it is not walked again: every character is
  // scanned at most once per kind and the pass stays linear.
  const unclosed = new Map<string, [number, number]>();
  QUOTED_KEY.lastIndex = 0;
  for (let m = QUOTED_KEY.exec(text); m; m = QUOTED_KEY.exec(text)) {
    const end = m.index + m[0].length;
    if (!isSecretKeyName((m[3] as string).trim())) continue;
    let bs = 0;
    while (bs < 16 && text[end + bs] === "\\") bs += 1;
    const quote = text[end + bs];
    let valueStart: number;
    let valueEnd: number;
    if (quote === '"' || quote === "'" || quote === "`") {
      valueStart = end + bs + 1;
      // At escaping depth d the opening quote has 2^d - 1 backslashes, and a quote is
      // the closing one when its backslash run is that many modulo 2^(d+1): one more
      // backslash pair is an escaped backslash, an odd excess is an inner quote.
      const period = (bs + 1) & bs ? 0 : 2 * (bs + 1);
      const kind = `${quote}${bs}`;
      const seen = unclosed.get(kind);
      let i = valueStart;
      valueEnd = -1;
      if (seen && valueStart >= seen[0] && valueStart < seen[1])
        i = text.length;
      while (i < text.length && i - valueStart <= MAX_QUOTED_VALUE) {
        const c = text[i];
        if (c === "\n" || c === "\r") break;
        if (c === quote) {
          const run = backslashesBefore(text, i);
          const own = i - run >= valueStart ? run : i - valueStart;
          if (period ? own % period === bs : own === bs) {
            valueEnd = i - bs;
            break;
          }
        }
        i += 1;
      }
      if (valueEnd === -1) {
        if (i < text.length) unclosed.set(kind, [valueStart, i]);
        else if (!seen || valueStart < seen[0] || valueStart >= seen[1])
          unclosed.set(kind, [valueStart, text.length]);
        // No closing quote on this line: redact up to the next whitespace.
        const ws = text
          .slice(valueStart, valueStart + MAX_QUOTED_VALUE)
          .search(/\s/);
        valueEnd =
          ws === -1
            ? Math.min(text.length, valueStart + MAX_QUOTED_VALUE)
            : valueStart + ws;
      }
    } else {
      if (bs > 0) continue;
      valueStart = end;
      const bare = /^[^\s"'`,;{}[\]\\]+/.exec(
        text.slice(end, end + MAX_QUOTED_VALUE),
      );
      if (!bare || NON_SECRET_BARE.test(bare[0])) continue;
      valueEnd = end + bare[0].length;
    }
    const value = text.slice(valueStart, valueEnd);
    if (valueEnd <= valueStart || keepQuotedValue(value)) continue;
    out += text.slice(last, valueStart) + REDACTED;
    last = valueEnd;
    QUOTED_KEY.lastIndex = Math.max(QUOTED_KEY.lastIndex, valueEnd);
  }
  return last === 0 ? text : out + text.slice(last);
}

/** Shannon entropy of `s` in bits per character. */
function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Whether a token next to a secret name looks generated: 20+ characters drawing on at
 * least two of lowercase, uppercase and digits, with at least 3.5 bits of entropy per
 * character. Only ever asked about a token directly after a secret name (the fallback
 * rule), never about free text, so commit shas, digests and ids elsewhere in a
 * transcript are kept.
 */
function looksGenerated(token: string): boolean {
  const classes =
    Number(/[a-z]/.test(token)) +
    Number(/[A-Z]/.test(token)) +
    Number(/\d/.test(token));
  return token.length >= 20 && classes >= 2 && entropy(token) >= 3.5;
}

type Rule = [RegExp, Replacement] | ((text: string) => string);

const SECRET_PATTERNS: Rule[] = [
  // PEM private keys (PKCS#1/#8, EC, OpenSSH, encrypted) and armored PGP private key
  // blocks (`-----BEGIN PGP PRIVATE KEY BLOCK-----`), each up to its footer.
  [
    // A block with no footer (a truncated paste, a key split across records) is
    // redacted to the end of the string rather than kept.
    /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g,
    REDACTED,
  ],
  [/(^|[\s"'(=:/])\/Users\/[^/\s]+(?=\/)/g, "$1~"],
  [/(^|[\s"'(=:/])\/home\/[^/\s]+(?=\/)/g, "$1~"],
  [/(^|[\s"'(=])([A-Z]:\\Users\\[^\\\s]+)(?=\\)/gi, "$1~"],
  // The token runs to the end of its characters, so a trailing `-`, `_` or `=` padding is
  // part of it (a `\b` end used to leave it behind); a sentence-ending dot is not.
  [
    /\bBearer\s+[A-Za-z0-9._~+/=-]{15,}[A-Za-z0-9_~+/=-](?![A-Za-z0-9_~+/=-])/gi,
    `Bearer ${REDACTED}`,
  ],
  // Provider key prefixes. The hyphen form covers OpenAI-style `sk-…` (`sk-proj-…`) and
  // Anthropic `sk-ant-…`; the underscore form
  // covers Stripe-style `sk_live_…`/`sk_test_…` (and rk_/pk_) which the hyphen pattern misses.
  [/\b(?:sk|rk|pk|ak)-[A-Za-z0-9_-]{20,}(?![A-Za-z0-9_-])/g, REDACTED],
  [/\b(?:(?:sk|rk|pk)_(?:live|test)_|whsec_)[A-Za-z0-9]{10,}\b/g, REDACTED],
  [/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, REDACTED],
  // AWS access/secret-access key IDs (AKIA long-term, ASIA temporary).
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, REDACTED],
  // GitHub fine-grained personal access tokens (`github_pat_…`); the classic and app
  // tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) are the rule above.
  [/\bgithub_pat_[A-Za-z0-9_]{22,}/g, REDACTED],
  // GitLab personal/project/group access tokens.
  [/\bglpat-[A-Za-z0-9_-]{20,}/g, REDACTED],
  // npm access tokens (`npm_` + 36).
  [/\bnpm_[A-Za-z0-9]{36}\b/g, REDACTED],
  // Hugging Face user access tokens (`hf_` + 34 letters).
  [/\bhf_[A-Za-z]{34}\b/g, REDACTED],
  // SendGrid API keys (`SG.` + 22 + `.` + 43).
  [/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g, REDACTED],
  // Cloudflare scannable credentials: `cfk_` (Global API Key), `cfut_` (user API token)
  // and `cfat_` (account API token), each a 40-character alphanumeric body and an
  // 8-character hex CRC32 checksum (53 characters for `cfut_`/`cfat_`). The body is taken
  // as 40 or more so a longer variant is still caught; the prefix keeps it tight.
  // Legacy unprefixed Cloudflare credentials (37-hex Global API Keys, 40-character API
  // tokens) have no shape of their own and are caught next to their name instead:
  // `X-Auth-Key: …`, `CLOUDFLARE_API_TOKEN=…`, `"api_token": "…"`, `Bearer …`.
  [/\bcf(?:k|ut|at)_[A-Za-z0-9]{40,}/g, REDACTED],
  // Slack tokens (xoxb/xoxp/xoxa/xoxr/xoxs/xoxe-… and app-level xapp-…).
  [/\b(?:xox[baprse]|xapp)-[A-Za-z0-9-]{10,}(?![A-Za-z0-9_-])/g, REDACTED],
  // Slack incoming webhook URLs carry their credential in the path; keep the host.
  [
    /(hooks\.slack\.com\/(?:services|workflows|triggers)\/)[A-Za-z0-9_/-]{8,}/g,
    `$1${REDACTED}`,
  ],
  // Capy API keys (`capy_…`), Cursor/Grok Bot routine keys (`crsr_…`) and Agent Relay
  // tokens (`relay_ag_…`, `relay_pa_…`, `relay_ws_…`, `relay_id_…`). Capy and Grok Bot
  // transcripts are uploaded to history, and a turn that set up a routine can echo its key.
  [/\b(?:capy|crsr)_[A-Za-z0-9_-]{16,}/g, REDACTED],
  [/\brelay_(?:ag|pa|ws|id)_[A-Za-z0-9._-]{16,}/g, REDACTED],
  // Capy automation webhook URLs carry their credential in the path: the URL itself is
  // the secret. Keep the host and route so the reference stays diagnosable. The last
  // character can't be a dot, so a sentence-ending period survives.
  [
    /(\/webhooks\/automations\/)[A-Za-z0-9._~-]{7,}[A-Za-z0-9_~-]/g,
    `$1${REDACTED}`,
  ],
  // Bare JWTs (`header.payload.signature`, header and payload base64url JSON, so `eyJ`),
  // e.g. a Capy session token echoed from /etc/capy/session-token. Matched as maximal
  // token runs (each character is consumed once, so it is linear) and split in code, so
  // there is no length cap a large token could slip past.
  [/[A-Za-z0-9_.-]{35,}/g, redactJwtsInRun],
  // Service-local relayhistory tokens. Distinct from URL userinfo / Bearer.
  [/\brth_(?:at|rt|st)_[A-Za-z0-9_]{8,}\b/g, REDACTED],
  // OAuth authorize URLs: keep host+path so "stuck at auth.openai.com/oauth/authorize"
  // remains diagnosable, redact the challenge/state/secret query values.
  [
    /([?&](?:code_challenge|code_verifier|state|client_secret|access_token|id_token|refresh_token|assertion)=)[^&\s]*/gi,
    `$1${REDACTED}`,
  ],
  // Google API keys (AIza + 35 chars).
  [/\bAIza[0-9A-Za-z_-]{30,}(?![A-Za-z0-9_-])/g, REDACTED],
  // Quoted secret keys in every JSON/YAML/Python form, at any escaping depth:
  // `"password": "…"`, `\"api_key\": \"…\"` (a JSON document inside a tool-result string),
  // `'token' => '…'`. The value is redacted, the key and quotes kept. See
  // `redactQuotedSecretValues`.
  redactQuotedSecretValues,
  // `Authorization: Basic …` / `Token …` / `Bot …` and other non-Bearer schemes (Bearer is
  // its own rule above): the credential after the scheme, keeping the scheme.
  [
    /(\bauthorization(?![A-Za-z0-9])[^A-Za-z0-9\r\n]{1,8}(?:Basic|Token|Bot|Digest|Negotiate|NTLM)\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
    `$1${REDACTED}`,
  ],
  // `<name>=<value>` / `<name>: <value>` secret assignments. The identifier may be prefixed
  // (STRIPE_KEY, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, DB_PASSWORD) — `(?:[A-Za-z0-9]+_)*`
  // absorbs the prefix segments so the trailing sensitive word still anchors. The leading `\b`
  // + required underscore segments means a bare word like `monkey=…` is NOT matched.
  [
    // `(?:[A-Za-z0-9]+_){0,8}` is bounded, not `*`: an unbounded prefix class in front of a
    // literal is the same quadratic shape fixed in the URL and email patterns. Eight
    // underscore-separated segments is far past any real identifier
    // (`AWS_SECRET_ACCESS_KEY` is three).
    /\b(?:[A-Za-z0-9]+_){0,8}(?:api[_-]?key|apikey|key|secret|token|password|passwd|passphrase|pwd|credentials?)\s*[:=]\s*["'`]?[^"'`\s,;]+/gi,
    (match) => {
      // Pick the separator POSITIONALLY (first `:` or `=`) — that is the real name/value
      // delimiter, since the identifier name contains neither. Choosing by `includes("=")`
      // mis-fires on a colon-assigned value whose body has `=` (base64 padding, common in
      // AWS secret keys / k8s/YAML dumps): indexOf would land inside the value and leak the
      // body before it.
      const idx = match.search(/[:=]/);
      const separator = match[idx];
      return `${match.slice(0, idx)}${separator}${REDACTED}`;
    },
  ],
  // Fallback: a generated-looking token (see `looksGenerated`) directly after a secret
  // name with only punctuation or a little whitespace between them, in shapes the
  // assignment rules do not parse: `--token <t>`, `password -> <t>`,
  // `API key <t>`. Only next to a secret name, so hashes and ids elsewhere are kept. The
  // token is bounded (a longer run is left whole) so each start stays O(1).
  [
    /(?<![A-Za-z0-9])((?:password|passwd|passphrase|secret|token|credentials?|api[_ -]?key|access[_ -]?key|private[_ -]?key|secret[_ -]?key|client[_ -]?secret|auth[_ -]?token|session[_ -]?token)(?![A-Za-z0-9_])[^A-Za-z0-9\r\n]{1,8})([A-Za-z0-9_+/=.-]{20,512})(?![A-Za-z0-9_+/=.-])/gi,
    (match, lead, token) =>
      looksGenerated(token as string) ? `${lead}${REDACTED}` : match,
  ],
  // A URL scheme is short by definition — RFC 3986 registers nothing close to 32 chars.
  // Leaving the scheme `[a-z0-9+.-]*` unbounded made this pattern QUADRATIC: on any long
  // run of scheme-legal characters the engine consumed to end-of-string hunting for `://`,
  // backtracked the whole way, then repeated from the next offset. That is O(n²), and it is
  // reachable from a single prompt: a 128 KB `AAAA…` prompt cost 21s of CPU here, which took
  // the Worker past its limit (Cloudflare 1102) and 503'd every push from the machine that
  // had it queued — permanently, since a failed batch never advances the cursor.
  // Bounding the scheme makes each start position O(1) and the whole pass linear.
  [/([a-z][a-z0-9+.-]{0,31}:\/\/[^:\s/@]+:)[^@\s/]+(@)/gi, `$1${REDACTED}$2`],
  // Token-only userinfo (`https://<token>@github.com/o/r`) is a credential too. Redact it
  // HERE, keeping the `@host`, rather than leaving it to the email rule below, which would
  // swallow the host along with the token and make the remote undiagnosable. `git@` is
  // the conventional, non-secret SSH user (`ssh://git@github.com/o/r`) and is kept.
  // Userinfo can never contain `?` or `#` (RFC 3986), so an `@` in a query or fragment
  // (`https://host/?to=bob@x.io`) is not mistaken for userinfo and the host survives.
  // Same bounded-scheme shape as the pattern above, so it is linear for the same reason.
  [/([a-z][a-z0-9+.-]{0,31}:\/\/)(?!git@)[^:\s/@?#]+(@)/gi, `$1${REDACTED}$2`],
  // Bounded for the same reason as the URL scheme above, and it is the same failure:
  // `[A-Z0-9._%+-]+` with no upper bound consumed every run of dotted/base64-ish text to
  // end-of-string looking for an `@`, backtracked, then repeated from the next word
  // boundary — quadratic on exactly the kind of blob that shows up in a captured prompt.
  // RFC 5321 caps a local part at 64 characters and a domain at 255, so bounding here
  // costs no real address.
  //
  // The leading lookahead keeps scp-style git remotes (`git@github.com:Org/repo.git`)
  // intact: redacting them turned every SSH remote into `[REDACTED]:Org/repo.git`. Only
  // the conventional, non-secret `git` SSH user followed by `:path` is exempt; any other
  // local part is a real address and stays redacted even when a colon follows it
  // (`bob@example.com:notes`), because a `:path` suffix alone does not make text a remote.
  // The trailing `\.?[A-Z0-9-]` check stops the engine from backtracking to a shorter
  // host so a match always covers the whole address.
  // The leading lookbehind leaves URL userinfo to the userinfo rules above: the only
  // userinfo they keep is `git@` (`ssh://git@github.com/o/r`), which is not an address.
  // Every lookaround is bounded (the remote check by the same RFC limits as the match),
  // so each start position stays O(1) and the pass stays linear.
  [
    /(?<!:\/\/)\b(?!git@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}:[\w~./-])[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}\b(?!\.?[A-Z0-9-])/gi,
    REDACTED,
  ],
  // Phone numbers, only in unambiguous shapes so IDs, dates and counts survive:
  // international with a leading `+` (E.164, 8-15 digits, optional separators), and
  // North American numbers with separators: (415) 555-0123, 415-555-0123, 415.555.0123.
  // The whole run after the `+` is taken: digit groups joined by one separator, with
  // parenthesised groups anywhere (`+44 (20) 7946 0958`, `+44 20 (7946) 0958`). It is
  // redacted if it holds at least 8 digits, so short labels survive; a run holding two
  // adjacent numbers is redacted whole rather than leaving the second one visible.
  // Groups are delimited, so the pattern cannot backtrack exponentially.
  [
    /(^|[^\w+])\+[1-9]\d*(?:[ .-]?\(\d{1,4}\)\d*|[ .-]\d+)*(?!\w|[.-]?\d)/g,
    (match, lead) =>
      (match.match(/\d/g)?.length ?? 0) >= 8 ? `${lead}${REDACTED}` : match,
  ],
  [
    /(^|[^\w.+-])(?:\([2-9]\d{2}\) ?|[2-9]\d{2}[.-])[2-9]\d{2}[.-]\d{4}(?!\w|[.-]?\d)/g,
    `$1${REDACTED}`,
  ],
  // Payment card numbers, after the phone rules: a card rule that ran first could
  // redact the tail of a phone plus the number beside it and leave the rest of the
  // phone unmatched. 13-19 digits, plain or grouped by one consistent space or
  // hyphen, with a known issuer prefix and length and a valid Luhn check digit
  // (`isCardNumber`). The match is a whole run of digit groups (so a card is never taken
  // out of a longer number, a decimal or a word); `redactCardsInRun` then redacts every
  // card in it, so an adjacent expiry date, CVV or second card cannot hide one.
  [
    /(^|[^\w.+-])(\d+(?:[ -]\d+)*)(?!\w|[.-]\d)/g,
    (_match, lead, run) => `${lead}${redactCardsInRun(run as string)}`,
  ],
];

/**
 * Issuer prefixes and lengths for the card rule: Visa, Mastercard (51-55 and 2221-2720),
 * American Express, Diners Club, JCB, Discover and UnionPay. Lengths are per brand so
 * that, for example, an 18-digit ID starting with 2 is never taken for a Mastercard.
 */
function knownIssuer(d: string): boolean {
  const n = d.length;
  if (n < 13 || n > 19) return false;
  const c = (k: number) => d.charCodeAt(k) - 48;
  const prefixes = [0, c(0), c(0) * 10 + c(1), c(0) * 100 + c(1) * 10 + c(2)];
  prefixes.push((prefixes[3] as number) * 10 + c(3));
  const p = (k: number) => prefixes[k] as number;
  const visa = d[0] === "4" && (n === 13 || n === 16 || n === 19);
  const mastercard =
    ((p(2) >= 51 && p(2) <= 55) || (p(4) >= 2221 && p(4) <= 2720)) && n === 16;
  const amex = (p(2) === 34 || p(2) === 37) && n === 15;
  const diners =
    ((p(3) >= 300 && p(3) <= 305) || [36, 38, 39].includes(p(2))) &&
    (n === 14 || n === 16);
  const jcb = p(4) >= 3528 && p(4) <= 3589 && n >= 16 && n <= 19;
  const discoverUnionPay =
    (p(4) === 6011 ||
      (p(3) >= 644 && p(3) <= 649) ||
      p(2) === 65 ||
      p(2) === 62) &&
    n >= 16 &&
    n <= 19;
  return visa || mastercard || amex || diners || jcb || discoverUnionPay;
}

/** A known issuer prefix and length (`knownIssuer`) and a valid Luhn check digit. */
function isCardDigits(digits: string): boolean {
  if (!knownIssuer(digits)) return false;
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/**
 * Whether `text` (digits, optionally grouped by one consistent space or hyphen) is a
 * plausible payment card number: a known issuer prefix and length and a valid Luhn
 * check digit.
 */
export function isCardNumber(text: string): boolean {
  let digits = "";
  let sep = "";
  for (const c of text) {
    if (c >= "0" && c <= "9") digits += c;
    else if ((c !== " " && c !== "-") || (sep && c !== sep)) return false;
    else sep = c;
  }
  return isCardDigits(digits);
}

/**
 * Redact every card number in `run` (digit groups separated by single spaces or
 * hyphens). A card starts at a group and spans whole groups joined by one consistent
 * separator; at each group the longest valid card wins, and groups that start none are
 * kept as they are. Each start looks at most 19 digits ahead, so this is linear.
 */
function redactCardsInRun(run: string): string {
  const groups = run.split(/[ -]/);
  const seps = run.replace(/\d+/g, "");
  let out = "";
  let i = 0;
  while (i < groups.length) {
    let end = -1;
    let digits = "";
    // Every issuer prefix starts with 2-6.
    const first = (groups[i] as string)[0] as string;
    for (
      let j = first >= "2" && first <= "6" ? i : groups.length;
      j < groups.length;
      j++
    ) {
      if (j > i + 1 && seps[j - 1] !== seps[i]) break;
      digits += groups[j];
      if (digits.length > 19) break;
      if (digits.length >= 13 && isCardDigits(digits)) end = j;
    }
    out += end === -1 ? groups[i] : REDACTED;
    const next = end === -1 ? i + 1 : end + 1;
    if (next < groups.length) out += seps[next - 1];
    i = next;
  }
  return out;
}

/**
 * A JSON number that is a card number becomes `[REDACTED]`. Only safe integers are
 * checked: a larger number has already lost digits in `JSON.parse`, so the exact card
 * number never reaches this point.
 */
export function scrubNumber(value: number): number | string {
  return Number.isSafeInteger(value) && value > 0 && isCardNumber(String(value))
    ? REDACTED
    : value;
}

/**
 * Hard bound on a single string handed to the scrubber. Every path into the store —
 * `content`, the task fields, and each string inside `record` via `scrubJson` — funnels
 * through `scrubText`, so bounding here bounds the whole ingest.
 *
 * 256 KiB is ~10x the p99.9 of real captured prompts (23 KB; nothing in a recent 6k-row
 * sample exceeded 33 KB), so this truncates no genuine history. It exists so that a single
 * pathological record cannot again wedge a machine's push forever the way the quadratic
 * scheme pattern did: even at Cloudflare's 100 MB request-body ceiling the scrub pass now
 * stays well inside the Worker CPU limit.
 */
export const MAX_SCRUB_CHARS = 262_144;

const TRUNCATION_NOTE = "[relayhistory: truncated";

const PEM_BEGIN = /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/g;
const PEM_END = /-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/g;

/**
 * Start of the first private-key block in `text` that the PEM rule cannot
 * close (its `-----END ...-----` footer is missing), or -1. Mirrors how the
 * lazy PEM pattern pairs each header with the next footer, left to right.
 */
function unclosedPrivateKeyStart(text: string): number {
  let pos = 0;
  for (;;) {
    PEM_BEGIN.lastIndex = pos;
    const begin = PEM_BEGIN.exec(text);
    if (!begin) return -1;
    PEM_END.lastIndex = begin.index + begin[0].length;
    const end = PEM_END.exec(text);
    if (!end) return begin.index;
    pos = end.index + end[0].length;
  }
}

/**
 * Truncate over-long input BEFORE the patterns run, cutting only after whitespace.
 *
 * Cutting mid-token would leave the leading fragment of a credential in the retained
 * prefix — short enough that no `{20,}`-style pattern matches it, so the scrubber would
 * silently stop protecting the very thing it exists to protect. Apart from the PEM rule,
 * no rule's match contains whitespace except as a separator before the secret (Bearer,
 * `key = value`), as a delimiter before it (home paths), or between the digit groups of
 * a card or phone number. So the cut falls only right after whitespace and never
 * between two digit groups (a digit or `)` before the whitespace, a digit or `(` after
 * it), which leaves every secret either wholly retained (and therefore scrubbed) or
 * wholly dropped.
 *
 * The cut therefore rewinds to the last whitespace before the limit however far back
 * that is. An input with no whitespace at all is one unbroken run (minified JSON, a
 * base64 dump) and is dropped whole rather than cut inside, because a credential can
 * sit anywhere in such a run. Cuts after whitespace never split a surrogate pair, since
 * every JavaScript whitespace character is in the BMP.
 *
 * A private key is the one multi-line secret: the PEM rule needs both delimiters, so a
 * block whose footer falls past the cut is withheld from its header on.
 *
 * The truncation is always announced in band so a reader can tell a truncated record
 * from a short one.
 */
/** Whether `value` may be cut before index `at` (see `boundForScrub`). */
function safeCut(value: string, at: number): boolean {
  return (
    /\s/.test(value[at - 1] as string) &&
    !(/[\d)]/.test(value[at - 2] ?? "") && /[\d(]/.test(value[at] ?? ""))
  );
}

function boundForScrub(value: string): string {
  if (value.length <= MAX_SCRUB_CHARS) {
    return value;
  }
  let cut = MAX_SCRUB_CHARS;
  while (cut > 0 && !safeCut(value, cut)) {
    cut -= 1;
  }
  const unclosed = unclosedPrivateKeyStart(value.slice(0, cut));
  if (unclosed !== -1) {
    cut = unclosed;
  }
  const dropped = value.length - cut;
  return `${value.slice(0, cut)}\n${TRUNCATION_NOTE} ${dropped} characters over the ${MAX_SCRUB_CHARS}-character scrub limit]`;
}

/** Whether `scrubText` will truncate this input (and announce it in band). */
export function exceedsScrubBound(value: string): boolean {
  return value.length > MAX_SCRUB_CHARS;
}

/**
 * Scrub one string. Each string is scrubbed on its own: a secret split across two
 * strings, JSON values or records (a token streamed as separate deltas, a value
 * concatenated only at display time) is not recognized, because neither part matches a
 * rule. Callers that assemble text from parts should scrub the assembled text.
 */
export function scrubText(value: string): string {
  return SECRET_PATTERNS.reduce(
    (text, rule) =>
      typeof rule === "function"
        ? rule(text)
        : text.replace(rule[0], rule[1] as any),
    boundForScrub(value),
  );
}

/**
 * Scrub every string value **and key** of a JSON value, and card numbers among its
 * numbers. Two keys that become identical after scrubbing are both kept: later ones get
 * a ` (2)`, ` (3)`… suffix, so no value is silently overwritten and no input is
 * rejected (a rejected record would wedge the push that carries it).
 */
export function scrubJson<T>(value: T): T {
  if (typeof value === "string") {
    return scrubText(value) as T;
  }
  if (typeof value === "number") {
    return scrubNumber(value) as T;
  }
  if (Array.isArray(value)) {
    return value.map((item) => scrubJson(item)) as T;
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    // Next suffix to try per scrubbed key, so many collisions stay linear.
    const nextSuffix = new Map<string, number>();
    for (const [key, item] of Object.entries(value)) {
      const base = scrubText(key);
      let name = base;
      if (Object.hasOwn(output, name)) {
        let n = nextSuffix.get(base) ?? 2;
        while (Object.hasOwn(output, `${base} (${n})`)) n++;
        name = `${base} (${n})`;
        nextSuffix.set(base, n + 1);
      }
      output[name] = scrubJson(item);
    }
    return output as T;
  }
  return value;
}

export function scrubRecord<T extends Record<string, unknown>>(
  record: T,
): Record<string, unknown> {
  const scrubbed = scrubJson(record);
  const output: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(scrubbed)) {
    if (key === "confidence") {
      continue;
    }
    if (DEFAULT_RECORD_ALLOWLIST.has(key)) {
      output[key] = stripPromotedConfidence(value);
    }
  }

  return output;
}

function stripPromotedConfidence(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => stripPromotedConfidence(item));
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      if (key !== "confidence") {
        output[key] = stripPromotedConfidence(item);
      }
    }
    return output;
  }
  return value;
}

const DEFAULT_RECORD_ALLOWLIST = new Set([
  "id",
  "eventId",
  "messageId",
  "requestId",
  "fingerprint",
  "idFingerprint",
  "source",
  "lens",
  "sessionId",
  "kind",
  "type",
  "ts",
  "startTs",
  "endTs",
  "writtenAt",
  "significance",
  "confidence",
  "tags",
  "model",
  "provider",
  "usage",
  "costUsdMicros",
  "toolName",
  "toolTarget",
  "toolStatus",
  "toolCalls",
  "toolError",
  "activity",
  "stopReason",
  "fidelity",
  "coverage",
  "relationshipType",
  "parentSessionId",
  "rootSessionId",
  "subagentId",
  "actorName",
  "actorRole",
  "filesTouched",
  "filesChanged",
  "codeChurn",
  "trace",
  "decision",
  "task",
  "taskRef",
  "taskTitle",
  "taskDescription",
  "taskStatus",
  "chapterId",
  "agent",
  "status",
  "commits",
  "sizes",
  "truncated",
]);
