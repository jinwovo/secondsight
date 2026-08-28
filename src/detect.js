/**
 * secondsight -- the analysis engine
 *
 * One entry point, analyze(text), returning everything the UI and the CLI need.
 * No I/O, no DOM, no dependencies: the same function backs the web page, the
 * command line and the test suite.
 *
 * The engine tries hard not to cry wolf. A variation selector after an emoji
 * is how emoji work. A zero-width non-joiner in Persian text is spelling. A
 * byte-order mark at offset zero is a byte-order mark. Context rules below
 * demote all of those, because a scanner that flags ordinary text is a scanner
 * people learn to ignore -- and the day it finds something real, they will.
 */

import {
  describe, hex, CONFUSABLES, HOMOGLYPH_SCRIPTS, LATIN_RE, KIND,
  SEVERITY, INFO, LOW, MEDIUM, HIGH, CRITICAL,
} from './catalog.js';
import {
  decodeTags, decodeVariationSelectors, decodeZeroWidth,
  findAnsiSequences, readIntent, textScore,
} from './decode.js';

export { SEVERITY, KIND, INFO, LOW, MEDIUM, HIGH, CRITICAL };

/** Kinds whose members occupy no visual space at all. */
const HIDDEN_KINDS = new Set([
  KIND.ZERO_WIDTH, KIND.TAGS, KIND.VS, KIND.BIDI,
  KIND.CONTROL, KIND.DEPRECATED, KIND.MARKER, KIND.NONCHAR, KIND.ANSI,
]);

const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;
const REGIONAL_INDICATOR = /[\u{1F1E6}-\u{1F1FF}]/u;
const ARABIC_INDIC = /\p{Script=Arabic}|\p{Script=Devanagari}|\p{Script=Bengali}|\p{Script=Gurmukhi}|\p{Script=Gujarati}|\p{Script=Tamil}|\p{Script=Telugu}|\p{Script=Kannada}|\p{Script=Malayalam}|\p{Script=Sinhala}|\p{Script=Thaana}/u;
const COMBINING = /\p{Mn}|\p{Me}/u;
const WORD_CHAR = /[\p{L}\p{N}_]/u;
const RTL_SCRIPT = /\p{Script=Arabic}|\p{Script=Hebrew}|\p{Script=Syriac}|\p{Script=Thaana}|\p{Script=Nko}|\p{Script=Samaritan}|\p{Script=Mandaic}|\p{Script=Adlam}/u;

// Directional controls, as numbers. Written as characters they would put real
// reordering marks into this file, invisible in every editor and every diff --
// the exact thing this module exists to find. See the note atop catalog.js.
const BIDI_CONTROLS = new Set([
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
  0x2066, 0x2067, 0x2068, 0x2069,
  0x200e, 0x200f, 0x061c,
]);

const VERDICTS = [
  { label: 'CLEAN', line: 'Both readers see the same thing.' },
  { label: 'MINOR', line: 'Cosmetic oddities only. Nothing hidden.' },
  { label: 'SUSPICIOUS', line: 'Characters here do not belong in ordinary text.' },
  { label: 'DANGEROUS', line: 'This text is carrying something you cannot see.' },
  { label: 'CRITICAL', line: 'A payload is hidden here, and it is addressed to a machine.' },
];

// ---------------------------------------------------------------------------
// Cells: one annotated record per codepoint
// ---------------------------------------------------------------------------

function buildCells(text) {
  const cells = [];
  let offset = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0);
    cells.push({
      i: cells.length,
      offset,
      cp,
      ch,
      info: describe(cp),
      confusable: null,
      benign: false,
      benignReason: '',
      hidden: false,
    });
    offset += ch.length;
  }
  for (const c of cells) {
    c.hidden = Boolean(c.info) && HIDDEN_KINDS.has(c.info.kind);
  }
  return cells;
}

/**
 * Demote characters that are doing their actual job.
 *
 * Everything here is a rule about neighbours, which is why it runs as a second
 * pass: the same codepoint is innocent or hostile depending on what sits next
 * to it, and nothing else in the engine gets to see that.
 */
function applyContext(cells) {
  const prevVisible = (i) => {
    for (let j = i - 1; j >= 0; j--) if (!cells[j].hidden) return cells[j];
    return null;
  };
  const nextVisible = (i) => {
    for (let j = i + 1; j < cells.length; j++) if (!cells[j].hidden) return cells[j];
    return null;
  };

  for (let i = 0; i < cells.length; i++) {
    const c = cells[i];
    if (!c.info) continue;

    // A byte-order mark at the very start of a document is a byte-order mark.
    if (c.cp === 0xfeff && i === 0) {
      c.benign = true;
      c.benignReason = 'byte-order mark at the start of the document';
      continue;
    }

    // VS-15 / VS-16 select text or emoji presentation for the character they
    // follow. That is the entire purpose of the codepoint.
    if (c.cp === 0xfe0e || c.cp === 0xfe0f) {
      const p = cells[i - 1];
      if (p && (PICTOGRAPHIC.test(p.ch) || /[#*0-9]/.test(p.ch))) {
        c.benign = true;
        c.benignReason = 'emoji or text presentation selector';
        continue;
      }
    }

    // ZWJ is the glue in emoji sequences: family, profession and flag emoji are
    // all several pictographs joined by one of these.
    if (c.cp === 0x200d) {
      const p = prevVisible(i);
      const n = nextVisible(i);
      if (p && n && PICTOGRAPHIC.test(p.ch) && PICTOGRAPHIC.test(n.ch)) {
        c.benign = true;
        c.benignReason = 'joiner inside an emoji sequence';
        continue;
      }
    }

    // ZWJ and ZWNJ carry meaning in Arabic and the Indic scripts -- they are
    // spelling there, not steganography.
    if (c.cp === 0x200c || c.cp === 0x200d) {
      const p = prevVisible(i);
      const n = nextVisible(i);
      if ((p && ARABIC_INDIC.test(p.ch)) || (n && ARABIC_INDIC.test(n.ch))) {
        c.benign = true;
        c.benignReason = 'joiner control in a script that uses one';
        continue;
      }
    }

    // Regional indicator pairs form flags and often carry a selector.
    if (c.cp === 0xfe0f) {
      const p = cells[i - 1];
      if (p && REGIONAL_INDICATOR.test(p.ch)) {
        c.benign = true;
        c.benignReason = 'part of a flag sequence';
      }
    }
  }
  return cells;
}

// ---------------------------------------------------------------------------
// Confusables
// ---------------------------------------------------------------------------

function markConfusables(cells) {
  for (const c of cells) {
    if (c.info) continue;              // already accounted for
    const table = CONFUSABLES.get(c.cp);
    if (table) {
      c.confusable = { to: table.to, script: table.script, via: 'script' };
      continue;
    }
    if (c.cp < 0x80) continue;
    // NFKC folds full-width Latin, the mathematical alphanumeric blocks,
    // circled and parenthesised letters and much else down to ASCII. Using it
    // saves this file from carrying a thousand-row lookalike table.
    const folded = c.ch.normalize('NFKC');
    if (folded !== c.ch && folded.length <= 3 && /^[\x21-\x7e]+$/.test(folded)) {
      c.confusable = { to: folded, script: 'compatibility', via: 'nfkc' };
    }
  }
  return cells;
}

/** Split text into word-like tokens, keeping each token's byte offset. */
function tokenizeWords(text) {
  const words = [];
  let current = '';
  let start = 0;
  let offset = 0;
  const flush = (end) => {
    if (current.length >= 2) words.push({ word: current, start, end });
    current = '';
  };
  for (const ch of text) {
    if (WORD_CHAR.test(ch)) {
      if (!current) start = offset;
      current += ch;
    } else {
      flush(offset);
    }
    offset += ch.length;
  }
  flush(offset);
  return words;
}

/** True when [start, end) overlaps any [lo, hi) range in the list. */
function overlapsAny(start, end, ranges) {
  return ranges.some(([lo, hi]) => start < hi && lo < end);
}

/**
 * Hostnames that read as one domain and resolve to another.
 *
 * The reveal here is punycode: a browser and a DNS resolver do not see the
 * pretty Unicode name, they see its ToASCII form, and `new URL().hostname`
 * computes exactly that -- in the browser and in Node alike, with no
 * dependency. When a host contains a letter drawn like ASCII but taken from
 * another alphabet, the name you read and the name that resolves are two
 * different strings, and this returns both.
 *
 * Legitimate internationalised domains -- Japanese, Arabic, Greek written in
 * their own script -- are left alone: none of their letters have an ASCII twin
 * in the confusables table, so there is nothing here to imitate.
 */
const HOST_RE =
  /(?<![\p{L}\p{N}._@-])(?:https?:\/\/)?((?:[\p{L}\p{N}][\p{L}\p{N}-]*\.)+\p{L}{2,})/giu;

function findHomographHosts(text) {
  const out = [];
  HOST_RE.lastIndex = 0;
  let m;
  while ((m = HOST_RE.exec(text)) !== null) {
    const host = m[1];
    const start = m.index + m[0].length - host.length;

    let imitates = '';
    let hasConfusable = false;
    let allProjectable = true;
    const scripts = new Set();
    for (const ch of host) {
      const cp = ch.codePointAt(0);
      if (cp < 0x80) { imitates += ch; continue; }
      const c = CONFUSABLES.get(cp);
      if (c && /[a-z0-9.-]/i.test(c.to)) {
        imitates += c.to;
        hasConfusable = true;
        scripts.add(c.script);
      } else {
        imitates += ch;
        allProjectable = false;
      }
    }
    // A homograph imitates an ASCII domain: every non-ASCII letter must be a
    // lookalike, and at least one must be. Otherwise it is an honest IDN.
    if (!hasConfusable || !allProjectable) continue;

    let puny = null;
    try { puny = new URL('http://' + host).hostname; } catch { /* not a host */ }
    if (!puny || !/^xn--|\bxn--/.test(puny)) continue;

    out.push({
      host, start, end: start + host.length,
      punycode: puny, imitates, scripts: [...scripts],
    });
  }
  return out;
}

/**
 * A single word written in two alphabets is the clearest homoglyph signal
 * there is, and it needs no lookalike table to spot.
 *
 * Only Latin is used as the anchor. Korean, Japanese and Chinese routinely mix
 * their own script with Latin inside one token, so those combinations are not
 * treated as suspicious.
 */
function findMixedScriptWords(text, hostSpans = []) {
  const out = [];
  for (const w of tokenizeWords(text)) {
    if (!LATIN_RE.test(w.word)) continue;
    if (overlapsAny(w.start, w.end, hostSpans)) continue;   // the URL finding owns it
    const foreign = [];
    for (const [name, re] of HOMOGLYPH_SCRIPTS) {
      if (re.test(w.word)) foreign.push(name);
    }
    if (foreign.length) out.push({ ...w, scripts: ['Latin', ...foreign] });
  }
  return out;
}

/**
 * Which scripts is this document actually written in?
 *
 * A script carrying a meaningful share of the letters is a language the author
 * is writing, not a disguise they are wearing.
 */
function nativeScripts(text) {
  const counts = new Map();
  let total = 0;
  for (const ch of text) {
    if (!/\p{L}/u.test(ch)) continue;
    total++;
    let bucket = LATIN_RE.test(ch) ? 'Latin' : null;
    if (!bucket) {
      for (const [name, re] of HOMOGLYPH_SCRIPTS) {
        if (re.test(ch)) { bucket = name; break; }
      }
    }
    if (bucket) counts.set(bucket, (counts.get(bucket) || 0) + 1);
  }
  const native = new Set();
  if (!total) return native;
  for (const [name, n] of counts) {
    if (n / total >= 0.2) native.add(name);
  }
  return native;
}

/**
 * Words containing no Latin at all, where every single character happens to
 * have an ASCII twin.
 *
 * This is the case mixed-script analysis cannot see: spell a domain or a
 * package name entirely in Cyrillic and there is no script boundary left to
 * catch. It is also the case most likely to be wrong, because plenty of real
 * Russian words are built from letters that resemble Latin ones -- so a script
 * that carries a fifth of the document is treated as the language it is, and
 * words in it are left alone.
 */
function findSpoofedWords(text, native = nativeScripts(text), hostSpans = []) {
  const out = [];
  for (const w of tokenizeWords(text)) {
    if (w.word.length < 4 || LATIN_RE.test(w.word)) continue;
    if (overlapsAny(w.start, w.end, hostSpans)) continue;   // the URL finding owns it
    let projected = '';
    let script = null;
    let ok = true;
    for (const ch of w.word) {
      const c = CONFUSABLES.get(ch.codePointAt(0));
      if (!c || !/[A-Za-z0-9]/.test(c.to)) { ok = false; break; }
      projected += c.to;
      script = script || c.script;
    }
    if (ok && !native.has(script)) out.push({ ...w, projected, script });
  }
  return out;
}

/** Letters and digits are impersonation. Punctuation is usually typography. */
function isLetterLookalike(conf) {
  return /[A-Za-z0-9]/.test(conf.to);
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

/** Maximal contiguous stretches of cells satisfying `pred`. */
function collectRuns(cells, pred) {
  const runs = [];
  let run = null;
  for (const c of cells) {
    if (pred(c)) {
      if (!run) run = { start: c.offset, cells: [] };
      run.cells.push(c);
    } else if (run) {
      runs.push(run);
      run = null;
    }
  }
  if (run) runs.push(run);
  return runs;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function finding(f) {
  return {
    id: f.id,
    title: f.title,
    severity: f.severity,
    kind: f.kind,
    count: f.count ?? 0,
    detail: f.detail || '',
    positions: f.positions || [],
    decoded: f.decoded ?? null,
    scheme: f.scheme ?? null,
    intents: f.intents || [],
    reference: f.reference || '',
    samples: f.samples || [],
  };
}

function payloadIntents(decoded) {
  return decoded ? readIntent(decoded) : [];
}

function analyzeTags(cells) {
  const runs = collectRuns(cells, (c) => c.info && c.info.kind === KIND.TAGS);
  if (!runs.length) return [];
  const all = runs.flatMap((r) => r.cells);
  const perRun = runs.map((r) => decodeTags(r.cells.map((c) => c.cp)));
  const global = decodeTags(all.map((c) => c.cp));
  const decoded = perRun.filter(Boolean).join(' / ') || global;
  const intents = payloadIntents(decoded);

  return [finding({
    id: 'tags-block',
    title: 'ASCII smuggling via the Unicode Tags block',
    severity: CRITICAL,
    kind: KIND.TAGS,
    count: all.length,
    positions: all.map((c) => c.offset),
    decoded,
    intents,
    reference: 'Unicode Tags block U+E0000-U+E007F',
    detail:
      'The Tags block mirrors printable ASCII one codepoint at a time. It renders as ' +
      'nothing in browsers, terminals and editors, so this text looks shorter than it ' +
      'is -- but a tokenizer reads every character of it as ordinary prose.',
  })];
}

function analyzeVariationSelectors(cells) {
  const active = cells.filter((c) => c.info && c.info.kind === KIND.VS && !c.benign);
  if (!active.length) return [];

  const runs = collectRuns(cells, (c) => c.info && c.info.kind === KIND.VS && !c.benign);
  const longest = Math.max(...runs.map((r) => r.cells.length));
  const decoded = decodeVariationSelectors(active.map((c) => c.cp));
  const readable = textScore(decoded) >= 0.85 && decoded.length >= 2;

  // One stray selector is a rendering quirk. A run of them is a byte stream.
  const severity = longest >= 4 ? CRITICAL : longest >= 2 ? HIGH : MEDIUM;

  return [finding({
    id: 'variation-selectors',
    title: readable
      ? 'Payload hidden in variation selectors'
      : 'Unexpected run of variation selectors',
    severity,
    kind: KIND.VS,
    count: active.length,
    positions: active.map((c) => c.offset),
    decoded: readable ? decoded : null,
    intents: readable ? payloadIntents(decoded) : [],
    reference: 'U+FE00-U+FE0F and U+E0100-U+E01EF',
    detail:
      'Variation selectors are invisible by design and there are exactly 256 of them, ' +
      'one per byte value. Attached to any character -- an emoji is the usual choice -- ' +
      'they carry an arbitrary byte string while the visible glyph renders normally.',
  })];
}

function analyzeZeroWidth(cells) {
  const active = cells.filter(
    (c) => c.info && c.info.kind === KIND.ZERO_WIDTH && !c.benign,
  );
  if (!active.length) return [];

  const zw = decodeZeroWidth(active.map((c) => c.cp));
  const decoded = zw && zw.text ? zw.text : null;
  const distinct = new Set(active.map((c) => c.cp)).size;

  let severity;
  if (decoded) severity = CRITICAL;
  else if (active.length >= 16 && distinct >= 2) severity = HIGH;
  else if (active.length >= 4) severity = MEDIUM;
  else severity = LOW;

  const detail = decoded
    ? 'A run of zero-width characters decoded cleanly to text. That is not something ' +
      'that happens by accident -- these characters were used as a data channel.'
    : distinct >= 2
      ? 'Several distinct zero-width characters appear together. That pattern is how ' +
        'binary data is smuggled through plain text, though no known encoding matched ' +
        'this particular run.'
      : 'Zero-width characters occupy no space and survive copy-paste. They are often ' +
        'residue from a rich-text editor, and just as often a marker or a tracking beacon.';

  return [finding({
    id: 'zero-width',
    title: decoded ? 'Text hidden in zero-width characters' : 'Zero-width characters present',
    severity,
    kind: KIND.ZERO_WIDTH,
    count: active.length,
    positions: active.map((c) => c.offset),
    decoded,
    scheme: zw ? zw.scheme : null,
    intents: payloadIntents(decoded),
    detail,
    samples: [...new Set(active.map((c) => c.info.abbr))].slice(0, 8),
  })];
}

function analyzeBidi(cells, text) {
  const bidi = cells.filter((c) => c.info && c.info.kind === KIND.BIDI);
  if (!bidi.length) return [];

  const OPEN = new Set([0x202a, 0x202b, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068]);
  const CLOSE = new Set([0x202c, 0x2069]);
  const OVERRIDE = new Set([0x202d, 0x202e]);

  let depth = 0;
  let unbalanced = false;
  for (const c of bidi) {
    if (OPEN.has(c.cp)) depth++;
    else if (CLOSE.has(c.cp)) { depth--; if (depth < 0) { unbalanced = true; depth = 0; } }
  }
  if (depth !== 0) unbalanced = true;

  const overrides = bidi.filter((c) => OVERRIDE.has(c.cp));
  const marksOnly = bidi.every((c) => c.cp === 0x200e || c.cp === 0x200f || c.cp === 0x061c);

  // Lines carrying a directional control are the ones worth showing side by side.
  const lines = text.split(/\r\n|\r|\n/);
  const affected = [];
  let lineStart = 0;
  for (let n = 0; n < lines.length; n++) {
    const line = lines[n];
    if ([...line].some((ch) => BIDI_CONTROLS.has(ch.codePointAt(0)))) {
      affected.push({ line: n + 1, text: line, start: lineStart });
    }
    lineStart += line.length + 1;
  }

  // The sharpest signal available: directional controls in a document with no
  // right-to-left text in it. Bidi formatting exists to lay out Arabic and
  // Hebrew alongside Latin. Where there is no Arabic and no Hebrew, there is
  // nothing legitimate for these characters to be doing.
  const hasRtl = RTL_SCRIPT.test(text);

  let severity;
  if (overrides.length) severity = CRITICAL;
  else if (!hasRtl) severity = HIGH;
  else if (unbalanced) severity = HIGH;
  else if (marksOnly) severity = LOW;
  else severity = MEDIUM;

  return [finding({
    id: 'bidi',
    title: overrides.length
      ? 'Bidirectional override: displayed order differs from stored order'
      : !hasRtl
        ? 'Directional controls with no right-to-left text to direct'
        : unbalanced
          ? 'Unbalanced bidirectional controls'
          : 'Bidirectional formatting characters',
    severity,
    kind: KIND.BIDI,
    count: bidi.length,
    positions: bidi.map((c) => c.offset),
    reference: overrides.length ? 'CVE-2021-42574 (Trojan Source)' : '',
    samples: affected.slice(0, 5).map((a) => 'line ' + a.line),
    detail: overrides.length
      ? 'A directional override changes the order characters are drawn in without ' +
        'changing the order they are stored in. Source code can be made to review one ' +
        'way and compile another -- the reviewer and the compiler read different programs.'
      : !hasRtl
        ? 'These characters reorder text for scripts that read right to left, and there ' +
          'is no such script anywhere in this document. An isolate can make a comment ' +
          'appear to end where it does not, which is enough to hide a line of code in ' +
          'plain sight of everyone who reviews it.'
        : unbalanced
          ? 'Directional controls open without closing. Everything after them keeps the ' +
            'chosen direction, including text the author never meant to affect.'
          : 'Directional formatting characters are legitimate in mixed Arabic, Hebrew ' +
            'and Latin text. Worth knowing about; not necessarily worth worrying about.',
  })];
}

function analyzeControls(cells) {
  const out = [];
  const controls = cells.filter(
    (c) => c.info && c.info.kind === KIND.CONTROL && c.cp !== 0x1b,
  );
  if (controls.length) {
    out.push(finding({
      id: 'control-characters',
      title: 'Control characters in text',
      severity: controls.some((c) => c.cp === 0x00 || c.cp === 0x08) ? HIGH : MEDIUM,
      kind: KIND.CONTROL,
      count: controls.length,
      positions: controls.map((c) => c.offset),
      samples: [...new Set(controls.map((c) => c.info.abbr))].slice(0, 8),
      detail:
        'C0 and C1 control characters have no business in ordinary text. NUL truncates ' +
        'strings, BACKSPACE rewrites what a terminal has already printed, and the rest ' +
        'are usually the wreckage of a mis-decoded byte stream.',
    }));
  }
  return out;
}

function analyzeAnsi(text) {
  const seqs = findAnsiSequences(text);
  if (!seqs.length) return [];
  const dangerous = seqs.filter((s) => s.dangerous);
  return [finding({
    id: 'ansi-escapes',
    title: dangerous.length
      ? 'ANSI escape sequences that can rewrite terminal output'
      : 'ANSI escape sequences',
    severity: dangerous.length ? HIGH : LOW,
    kind: KIND.ANSI,
    count: seqs.length,
    positions: seqs.map((s) => s.index),
    samples: [...new Set(seqs.map((s) => s.kind))].slice(0, 8),
    detail:
      'A terminal is a renderer, and it can be told to lie. Cursor movement overwrites ' +
      'lines that have already scrolled past, SGR 8 conceals text outright, and an ' +
      'OSC 8 hyperlink shows one destination while pointing at another. If this text ' +
      'is ever cat-ed or printed to a log, what appears on screen is not what is stored.',
  })];
}

/**
 * Homoglyph reporting is where a naive scanner destroys its own credibility.
 *
 * A Cyrillic "a" is only interesting next to Latin letters. On its own it is
 * Russian. Flagging every Cyrillic and Greek character as "imitating ASCII"
 * would mark every word of Russian and Greek prose ever written as an attack,
 * so the finding is driven by word-level context, never by a bare table hit.
 *
 * Curly quotes and en-dashes are split off separately. In prose they are
 * correct typography; in code they are the reason a paste will not run. Worth
 * saying, not worth alarming anyone about.
 */
/**
 * Homograph domains. Returns the finding (or nothing) and the byte spans of
 * the flagged hosts, so the word-level confusable checks can defer to it
 * instead of reporting the same characters twice.
 */
function analyzeUrls(text) {
  const hosts = findHomographHosts(text);
  if (!hosts.length) return { findings: [], spans: [] };

  const spans = hosts.map((h) => [h.start, h.end]);
  const f = finding({
    id: 'homograph-url',
    title: 'Homograph domain: the link is not where it appears to go',
    severity: HIGH,
    kind: KIND.CONFUSABLE,
    count: hosts.length,
    positions: hosts.map((h) => h.start),
    samples: hosts.slice(0, 5).map((h) => h.host + '  ->  ' + h.punycode),
    reference: 'IDN homograph attack',
    detail:
      'These hostnames contain letters from another alphabet drawn identically to ASCII. ' +
      'A browser and a DNS resolver do not use the name you read -- they use its punycode ' +
      'form, shown above. So "' + hosts[0].host + '" looks like "' + hosts[0].imitates +
      '" and resolves to "' + hosts[0].punycode + '", somewhere else entirely. This is how ' +
      'a phishing link survives a careful second look.',
  });
  return { findings: [f], spans };
}

function analyzeConfusables(cells, text, hostSpans = []) {
  const out = [];
  const mixed = findMixedScriptWords(text, hostSpans);
  const spoofed = findSpoofedWords(text, nativeScripts(text), hostSpans);

  const punct = cells.filter(
    (c) => c.confusable && c.confusable.via === 'script' && !isLetterLookalike(c.confusable),
  );
  const compatLetters = cells.filter(
    (c) => c.confusable && c.confusable.via === 'nfkc' && isLetterLookalike(c.confusable),
  );

  if (mixed.length) {
    out.push(finding({
      id: 'mixed-script',
      title: 'A single word written in two alphabets',
      severity: HIGH,
      kind: KIND.CONFUSABLE,
      count: mixed.length,
      positions: mixed.map((m) => m.start),
      samples: mixed.slice(0, 6).map((m) => m.word + '  [' + m.scripts.join(' + ') + ']'),
      detail:
        'Mixing scripts inside one word is how a lookalike domain, package name or ' +
        'identifier is built. The word reads correctly, compares unequal to the one it ' +
        'imitates, and that difference is the entire point.',
    }));
  }

  if (spoofed.length) {
    out.push(finding({
      id: 'spoofed-word',
      title: 'Words that read as Latin but contain none',
      severity: MEDIUM,
      kind: KIND.CONFUSABLE,
      count: spoofed.length,
      positions: spoofed.map((s) => s.start),
      samples: spoofed.slice(0, 6).map((s) => s.word + '  reads as  ' + s.projected),
      detail:
        'Every character in these words has an ASCII twin, and not one of them is Latin. ' +
        'That is how a domain or package name is cloned without leaving a script ' +
        'boundary to catch. It is also, sometimes, just ordinary Cyrillic or Greek text ' +
        'that happens to be spelled from lookalike letters -- worth a glance either way.',
    }));
  }

  if (compatLetters.length) {
    out.push(finding({
      id: 'compatibility-forms',
      title: 'Full-width or styled letters standing in for ASCII',
      severity: MEDIUM,
      kind: KIND.CONFUSABLE,
      count: compatLetters.length,
      positions: compatLetters.map((c) => c.offset),
      samples: [...new Set(compatLetters.map((c) => c.confusable.to))].slice(0, 12),
      detail:
        'Full-width Latin, mathematical alphanumerics and circled letters read as normal ' +
        'text to a person and as different codepoints to everything else. Sometimes a ' +
        'stylistic choice; routinely a way past a keyword filter that only knows ASCII.',
    }));
  }

  if (punct.length) {
    out.push(finding({
      id: 'typographic-punctuation',
      title: 'Typographic punctuation in place of ASCII',
      severity: LOW,
      kind: KIND.CONFUSABLE,
      count: punct.length,
      positions: punct.map((c) => c.offset),
      samples: [...new Set(punct.map((c) => c.confusable.to))].slice(0, 12),
      detail:
        'Curly quotes, en-dashes and their relatives. Correct in prose and fatal in ' +
        'code -- this is the usual reason a snippet copied out of a document, a chat ' +
        'window or a PDF refuses to parse.',
    }));
  }

  return out;
}

function analyzeSpaces(cells) {
  const spaces = cells.filter((c) => c.info && c.info.kind === KIND.SPACE);
  if (!spaces.length) return [];
  return [finding({
    id: 'unusual-spaces',
    title: 'Spaces that are not the space character',
    severity: LOW,
    kind: KIND.SPACE,
    count: spaces.length,
    positions: spaces.map((c) => c.offset),
    samples: [...new Set(spaces.map((c) => c.info.abbr))].slice(0, 8),
    detail:
      'These render as whitespace but are not U+0020. They are the usual reason code ' +
      'copied out of a document, a chat client or a PDF refuses to run, and they let ' +
      'two identifiers look identical while comparing unequal.',
  })];
}

function analyzeMisc(cells, text) {
  const out = [];

  const pua = cells.filter((c) => c.info && c.info.kind === KIND.PUA);
  if (pua.length) {
    out.push(finding({
      id: 'private-use',
      title: 'Private Use Area characters',
      severity: MEDIUM,
      kind: KIND.PUA,
      count: pua.length,
      positions: pua.map((c) => c.offset),
      detail:
        'Unicode assigns no meaning to these codepoints. They render as whatever a ' +
        'private font decides, or as nothing at all, and they are a convenient channel ' +
        'for data that is meant to survive a copy without being read.',
    }));
  }

  const nonchar = cells.filter((c) => c.info && c.info.kind === KIND.NONCHAR);
  if (nonchar.length) {
    out.push(finding({
      id: 'noncharacters',
      title: 'Unicode noncharacters',
      severity: HIGH,
      kind: KIND.NONCHAR,
      count: nonchar.length,
      positions: nonchar.map((c) => c.offset),
      detail:
        'These codepoints are permanently reserved as non-characters. Nothing should ' +
        'ever emit them, and different parsers disagree about what to do with them -- ' +
        'which is precisely why they turn up in filter-evasion payloads.',
    }));
  }

  const deprecated = cells.filter((c) => c.info && c.info.kind === KIND.DEPRECATED);
  if (deprecated.length) {
    out.push(finding({
      id: 'deprecated-format',
      title: 'Deprecated format characters',
      severity: MEDIUM,
      kind: KIND.DEPRECATED,
      count: deprecated.length,
      positions: deprecated.map((c) => c.offset),
      detail: 'Unicode deprecated these. Modern software does not produce them.',
    }));
  }

  const markers = cells.filter(
    (c) => c.info && c.info.kind === KIND.MARKER && c.cp >= 0xfff9 && c.cp <= 0xfffb,
  );
  if (markers.length) {
    out.push(finding({
      id: 'interlinear-annotation',
      title: 'Interlinear annotation characters',
      severity: HIGH,
      kind: KIND.MARKER,
      count: markers.length,
      positions: markers.map((c) => c.offset),
      detail:
        'Text between these markers is hidden by most renderers and kept by most ' +
        'parsers -- a bracket pair that makes anything inside it disappear.',
    }));
  }

  // Stacked combining marks: Zalgo, and a cheap way to break a text renderer.
  //
  // Counted over cells rather than raw characters so that variation selectors
  // are not counted twice. They carry the nonspacing-mark category, so a naive
  // pass reports a 200-byte payload as a 200-deep accent stack -- one finding
  // wearing two hats, which is how a report loses the reader's trust.
  let stack = 0;
  let worst = 0;
  let worstAt = -1;
  for (const c of cells) {
    if (!c.info && COMBINING.test(c.ch)) {
      stack++;
      if (stack > worst) { worst = stack; worstAt = c.offset; }
    } else if (!c.info) {
      stack = 0;
    }
  }
  if (worst >= 5) {
    out.push(finding({
      id: 'combining-stack',
      title: 'Deeply stacked combining marks',
      severity: worst >= 12 ? HIGH : MEDIUM,
      kind: KIND.COMBINING,
      count: worst,
      positions: worstAt >= 0 ? [worstAt] : [],
      detail:
        worst + ' combining marks sit on a single base character. Beyond a handful this ' +
        'is either decorative vandalism or a deliberate attempt to overflow a text ' +
        'renderer, and it spills far outside its own line.',
    }));
  }

  return out;
}

function analyzeNormalization(text) {
  const out = [];
  if (text.normalize('NFC') !== text) {
    out.push(finding({
      id: 'not-nfc',
      title: 'Text is not in normalised form',
      severity: LOW,
      kind: 'normalization',
      count: 1,
      detail:
        'The same characters can be stored more than one way -- one codepoint, or a ' +
        'base plus a combining mark. Two strings that look identical here will compare ' +
        'unequal until something normalises them, and not everything does.',
    }));
  }
  const nfkc = text.normalize('NFKC');
  if (nfkc !== text && nfkc !== text.normalize('NFC')) {
    out.push(finding({
      id: 'nfkc-unstable',
      title: 'Compatibility characters change under normalisation',
      severity: LOW,
      kind: 'normalization',
      count: 1,
      detail:
        'Normalising this text would rewrite some of it. Where one system normalises ' +
        'and another does not, a value can pass validation in one form and take effect ' +
        'in another.',
    }));
  }
  return out;
}

function analyzeLineEndings(text) {
  const crlf = (text.match(/\r\n/g) || []).length;
  const lf = (text.match(/(?<!\r)\n/g) || []).length;
  const cr = (text.match(/\r(?!\n)/g) || []).length;
  const kinds = [crlf && 'CRLF', lf && 'LF', cr && 'CR'].filter(Boolean);
  if (kinds.length < 2) return [];
  return [finding({
    id: 'mixed-line-endings',
    title: 'Mixed line endings',
    severity: INFO,
    kind: 'normalization',
    count: crlf + lf + cr,
    samples: kinds.map((k) => k + ': ' + ({ CRLF: crlf, LF: lf, CR: cr })[k]),
    detail: 'More than one line-ending convention in one document.',
  })];
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Analyse a string.
 *
 * Returns cells for rendering, findings for reporting, and a verdict. Nothing
 * here touches the network or the filesystem.
 */
export function analyze(text) {
  if (typeof text !== 'string') text = String(text ?? '');

  const cells = markConfusables(applyContext(buildCells(text)));

  // Homograph hosts are found first: the confusable word checks defer to the
  // URL finding for characters inside a flagged host, so the same letters are
  // never reported twice.
  const urls = analyzeUrls(text);

  const findings = [
    ...analyzeTags(cells),
    ...analyzeVariationSelectors(cells),
    ...analyzeZeroWidth(cells),
    ...analyzeBidi(cells, text),
    ...analyzeAnsi(text),
    ...analyzeControls(cells),
    ...urls.findings,
    ...analyzeConfusables(cells, text, urls.spans),
    ...analyzeMisc(cells, text),
    ...analyzeSpaces(cells),
    ...analyzeNormalization(text),
    ...analyzeLineEndings(text),
  ];

  // A hidden payload that reads like an instruction is worse than one that
  // reads like a serial number. Say so, rather than burying it in the detail.
  for (const f of findings) {
    if (f.intents.length && f.severity < CRITICAL) f.severity = CRITICAL;
  }

  findings.sort((a, b) => b.severity - a.severity || b.count - a.count);

  const hiddenCells = cells.filter((c) => c.hidden && !c.benign);
  const benignCells = cells.filter((c) => c.hidden && c.benign);
  const maxSeverity = findings.length ? Math.max(...findings.map((f) => f.severity)) : -1;
  const verdict = maxSeverity >= 0 ? VERDICTS[maxSeverity] : VERDICTS[0];

  return {
    text,
    cells,
    findings,
    verdict: {
      severity: maxSeverity,
      label: maxSeverity < 0 ? 'CLEAN' : verdict.label,
      line: maxSeverity < 0 ? VERDICTS[0].line : verdict.line,
    },
    stats: {
      codepoints: cells.length,
      units: text.length,
      bytes: new TextEncoder().encode(text).length,
      visible: cells.length - hiddenCells.length - benignCells.length,
      hidden: hiddenCells.length,
      benignHidden: benignCells.length,
      confusables: cells.filter((c) => c.confusable).length,
      findings: findings.length,
    },
  };
}

/** The text as a human sees it: every zero-width character removed. */
export function visibleText(result) {
  return result.cells.filter((c) => !c.hidden).map((c) => c.ch).join('');
}

/**
 * What a person actually has in front of them, for side-by-side display.
 *
 * Same as visibleText except that directional controls are kept, because they
 * change what gets drawn and that is the entire point of showing the two
 * readings next to each other.
 *
 * Dropping the rest is also what makes the comparison safe to render. Asking a
 * browser to paint several thousand Tags-block codepoints sends it hunting
 * through every installed font for glyphs that do not exist, and it will hang
 * trying. The characters contribute nothing to what a human sees, which is
 * exactly why they are worth removing here and worth alarming about elsewhere.
 */
export function humanText(result) {
  return result.cells
    .filter((c) => !c.hidden || c.benign || (c.info && c.info.kind === KIND.BIDI))
    .map((c) => c.ch)
    .join('');
}

export { hex };
