/**
 * secondsight -- payload decoders
 *
 * Warning that "this text contains 76 invisible characters" is the easy half
 * and the useless half. What a reader actually needs is what those characters
 * say. Every function here takes a run of invisible codepoints and tries to
 * turn it back into the text somebody hid.
 *
 * Zero dependencies. Pure ASCII source, and control characters are written as
 * \x1b and \x07 escapes rather than as themselves -- the first draft of this
 * file had real ESC bytes sitting in the regex literal, invisible in every
 * editor and diff, which is exactly the problem this program exists to find.
 */

/** Printable-text ratio, used to decide whether a decode attempt worked. */
export function textScore(s) {
  const chars = [...s];
  if (!chars.length) return 0;
  let ok = 0;
  for (const ch of chars) {
    const cp = ch.codePointAt(0);
    if (cp === 0x09 || cp === 0x0a || cp === 0x0d) { ok++; continue; }
    if (cp >= 0x20 && cp <= 0x7e) { ok++; continue; }
    // Letters from any script count too -- payloads are not always ASCII.
    if (cp > 0x7f && /\p{L}|\p{N}|\p{P}|\p{Zs}/u.test(ch)) ok += 0.9;
  }
  return ok / chars.length;
}

/** A decode is only reported when it clearly reads as text rather than noise. */
function plausible(s, minLength = 2) {
  return [...s].length >= minLength && textScore(s) >= 0.85;
}

// ---------------------------------------------------------------------------
// Tags block -- U+E0000 plus ASCII
// ---------------------------------------------------------------------------

/**
 * The Tags block is a shadow copy of printable ASCII. U+E0041 is "A" with the
 * high bits set: it renders as absolutely nothing and tokenizes as a letter.
 * Decoding it is a subtraction.
 */
export function decodeTags(codepoints) {
  let out = '';
  for (const cp of codepoints) {
    if (cp === 0xe0001 || cp === 0xe007f) continue;   // LANGUAGE TAG / CANCEL TAG
    if (cp < 0xe0000 || cp > 0xe007f) continue;
    const code = cp - 0xe0000;
    if (code >= 0x20 && code <= 0x7e) out += String.fromCharCode(code);
    else if (code === 0x09 || code === 0x0a || code === 0x0d) out += String.fromCharCode(code);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Variation selectors -- 256 invisible codepoints, one per byte value
// ---------------------------------------------------------------------------

/**
 * VS-1..16 live at U+FE00..U+FE0F and VS-17..256 at U+E0100..U+E01EF. Between
 * them they cover exactly 0..255, so a run of them is a byte string. Attach
 * that run to any emoji and the emoji still renders normally while carrying a
 * payload of arbitrary length.
 */
export function decodeVariationSelectors(codepoints) {
  const bytes = [];
  for (const cp of codepoints) {
    if (cp >= 0xfe00 && cp <= 0xfe0f) bytes.push(cp - 0xfe00);
    else if (cp >= 0xe0100 && cp <= 0xe01ef) bytes.push(cp - 0xe0100 + 16);
  }
  if (!bytes.length) return '';
  return new TextDecoder('utf-8', { fatal: false }).decode(Uint8Array.from(bytes));
}

// ---------------------------------------------------------------------------
// Zero-width binary
// ---------------------------------------------------------------------------

const ZW_ALPHABET = [0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x00ad, 0x180e];

function bitsToString(bits, msbFirst) {
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) {
      b = (b << 1) | bits[i + (msbFirst ? j : 7 - j)];
    }
    bytes.push(b);
  }
  if (!bytes.length) return '';
  return new TextDecoder('utf-8', { fatal: false }).decode(Uint8Array.from(bytes));
}

/**
 * There is no single standard for hiding data in zero-width characters, so
 * rather than guess one, this tries every layout the common libraries use and
 * keeps whichever produces something that reads like text.
 *
 * Two-symbol alphabets are binary (both bit assignments, both bit orders);
 * three and four symbols pack two bits per character. Anything else is
 * reported honestly as present-but-not-decoded rather than forced into a
 * guess -- a wrong decode would be worse than none.
 */
export function decodeZeroWidth(codepoints) {
  const seq = codepoints.filter((cp) => ZW_ALPHABET.includes(cp));
  if (seq.length < 8) return null;

  const alphabet = [...new Set(seq)].sort((a, b) => a - b);
  const attempts = [];

  if (alphabet.length === 2) {
    for (const flip of [false, true]) {
      for (const msbFirst of [true, false]) {
        const bits = seq.map((cp) => {
          const v = cp === alphabet[0] ? 0 : 1;
          return flip ? 1 - v : v;
        });
        attempts.push({
          text: bitsToString(bits, msbFirst),
          scheme: 'binary, ' + (msbFirst ? 'MSB' : 'LSB') + '-first' + (flip ? ', inverted' : ''),
        });
      }
    }
  } else if (alphabet.length === 3 || alphabet.length === 4) {
    const alpha4 = alphabet.slice(0, 4);
    for (const msbFirst of [true, false]) {
      const bits = [];
      for (const cp of seq) {
        const v = alpha4.indexOf(cp);
        if (v < 0) continue;
        bits.push((v >> 1) & 1, v & 1);
      }
      attempts.push({
        text: bitsToString(bits, msbFirst),
        scheme: 'base-4, ' + (msbFirst ? 'MSB' : 'LSB') + '-first',
      });
    }
  }

  let best = null;
  for (const a of attempts) {
    if (!plausible(a.text, 3)) continue;
    const score = textScore(a.text);
    if (!best || score > best.score) best = { ...a, score };
  }
  if (best) return { text: best.text, scheme: best.scheme, count: seq.length };
  return { text: '', scheme: null, count: seq.length };
}

// ---------------------------------------------------------------------------
// ANSI escape sequences
// ---------------------------------------------------------------------------

// ESC, then either a CSI sequence, an OSC string (terminated by BEL or ST), or
// a single-character Fe escape.
const ANSI_RE =
  /\x1b(?:\[([0-9;?<>=]*)[ -/]*([@-~])|\]([\s\S]*?)(?:\x07|\x1b\\|$)|([@-Z\\-_]))/g;

const CURSOR_FINALS = new Set(['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'f', 'd', 's', 'u']);

/**
 * A terminal is a renderer, and like any renderer it can be told to lie.
 * Cursor movement rewrites what a line appears to say after it has already
 * been printed, SGR 8 conceals text outright, and an OSC 8 hyperlink displays
 * one URL while pointing somewhere else entirely.
 */
export function findAnsiSequences(s) {
  const out = [];
  ANSI_RE.lastIndex = 0;
  let m;
  while ((m = ANSI_RE.exec(s)) !== null) {
    const [raw, csiParams, csiFinal, oscBody, simpleFinal] = m;
    let kind = 'escape sequence';
    let detail = '';
    let dangerous = false;

    if (oscBody !== undefined) {
      const [num, ...rest] = oscBody.split(';');
      if (num === '8') {
        kind = 'OSC 8 hyperlink';
        const target = rest.slice(1).join(';');
        detail = target
          ? 'shows link text while pointing at ' + target
          : 'closes a hyperlink';
        dangerous = Boolean(target);
      } else if (num === '0' || num === '1' || num === '2') {
        kind = 'OSC window title';
        detail = 'rewrites the terminal title';
        dangerous = true;
      } else if (num === '52') {
        kind = 'OSC 52 clipboard';
        detail = 'writes to the system clipboard';
        dangerous = true;
      } else {
        kind = 'OSC ' + num;
        detail = 'operating system command';
      }
    } else if (csiFinal) {
      const params = csiParams || '';
      if (csiFinal === 'm') {
        kind = 'SGR colour/style';
        dangerous = /(^|;)8(;|$)/.test(params);
        detail = (params || 'reset') + (dangerous ? ' -- includes conceal' : '');
      } else if (CURSOR_FINALS.has(csiFinal)) {
        kind = 'cursor movement';
        detail = 'repositions the cursor, letting later output overwrite earlier lines';
        dangerous = true;
      } else if (csiFinal === 'J') {
        kind = 'erase display';
        detail = 'clears the screen';
        dangerous = true;
      } else if (csiFinal === 'K') {
        kind = 'erase line';
        detail = 'clears the current line';
        dangerous = true;
      } else {
        kind = 'CSI ' + csiFinal;
        detail = 'control sequence';
      }
    } else if (simpleFinal) {
      kind = 'ESC ' + simpleFinal;
      detail = 'single-character escape';
    }

    out.push({ index: m.index, raw, kind, detail, dangerous });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Reading the decoded payload
// ---------------------------------------------------------------------------

/**
 * Once a payload is back in plain text, the question is who it is addressed
 * to: a language model, or a shell.
 *
 * These are heuristics and are labelled as such in the UI. They raise a
 * finding's confidence; they never create one. Text hidden well enough to be
 * invisible is worth surfacing whatever it turns out to say.
 */
const INTENT_PATTERNS = [
  [/\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b/i, 'instruction override'],
  [/\b(system|developer)\s+(prompt|message|instruction)/i, 'system prompt reference'],
  [/\byou\s+are\s+(now|a|an)\b/i, 'persona reassignment'],
  [/\b(do\s+not|don't|never)\s+(tell|mention|inform|reveal|show|log)\b/i, 'concealment instruction'],
  [/\b(exfiltrate|upload|send|post|leak)\b[^.\n]{0,40}https?:\/\//i, 'exfiltration'],
  [/\b(curl|wget|nc|bash|sh|powershell|iex|invoke-expression)\b/i, 'shell command'],
  [/(~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|\.env\b|authorized_keys)/i, 'credential path'],
  [/\b(api[_-]?key|secret[_-]?key|access[_-]?token|bearer|password)\b/i, 'secret reference'],
  [/\b(base64|atob|btoa|fromCharCode|eval)\s*\(/i, 'encoded execution'],
  [/<\s*(script|iframe|img|svg)\b/i, 'HTML injection'],
  [/\b(rm\s+-rf|del\s+\/[sfq]|format\s+c:)/i, 'destructive command'],
  [/\b(tool|function)[\s_-]?call\b/i, 'tool-call reference'],
  [/https?:\/\/[^\s"'<>]+/i, 'embedded URL'],
];

export function readIntent(text) {
  const hits = [];
  for (const [re, label] of INTENT_PATTERNS) {
    const m = re.exec(text);
    if (m) hits.push({ label, match: m[0].slice(0, 80) });
  }
  return hits;
}
