/**
 * secondsight -- codepoint catalog
 *
 * Zero dependencies. The same module runs in Node and in the browser.
 *
 * This file is pure ASCII, and every codepoint it describes is written as a
 * number rather than as the character itself. That is not a style preference.
 * A homoglyph table typed out as glyphs is a table nobody can review: U+037E
 * GREEK QUESTION MARK and an ASCII semicolon are the same picture. Numbers are
 * auditable. Pictures are not. A tool that hunts invisible characters has no
 * business smuggling any through its own source.
 */

export const SEVERITY = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export const INFO = 0;
export const LOW = 1;
export const MEDIUM = 2;
export const HIGH = 3;
export const CRITICAL = 4;

/** Character families. Drives colour, grouping and explanation in the UI. */
export const KIND = {
  TAGS: 'tags',
  VS: 'variation-selector',
  ZERO_WIDTH: 'zero-width',
  BIDI: 'bidi',
  CONTROL: 'control',
  SPACE: 'space',
  LINEBREAK: 'linebreak',
  DEPRECATED: 'deprecated',
  PUA: 'private-use',
  NONCHAR: 'noncharacter',
  MARKER: 'marker',
  COMBINING: 'combining',
  CONFUSABLE: 'confusable',
  ANSI: 'ansi',
};

const K = KIND;

/**
 * Individually named codepoints.
 * [codepoint, abbreviation, official name, kind, base severity, note]
 *
 * "Base severity" is only a starting point. detect.js raises and lowers it
 * from context -- one ZWJ between two emoji is not the same finding as forty
 * of them wedged into a config file.
 */
const TABLE = [
  // ---- C0 controls (tab, newline and carriage return are handled elsewhere)
  [0x0000, 'NUL', 'NULL', K.CONTROL, HIGH, 'Terminates C strings; routinely truncates a value halfway through a parser.'],
  [0x0001, 'SOH', 'START OF HEADING', K.CONTROL, MEDIUM, ''],
  [0x0002, 'STX', 'START OF TEXT', K.CONTROL, MEDIUM, ''],
  [0x0003, 'ETX', 'END OF TEXT', K.CONTROL, MEDIUM, ''],
  [0x0004, 'EOT', 'END OF TRANSMISSION', K.CONTROL, MEDIUM, ''],
  [0x0005, 'ENQ', 'ENQUIRY', K.CONTROL, MEDIUM, ''],
  [0x0006, 'ACK', 'ACKNOWLEDGE', K.CONTROL, MEDIUM, ''],
  [0x0007, 'BEL', 'BELL', K.CONTROL, MEDIUM, 'Rings the terminal bell.'],
  [0x0008, 'BS', 'BACKSPACE', K.CONTROL, HIGH, 'Erases the previous character in a terminal -- it can rewrite what a log appears to say.'],
  [0x000b, 'VT', 'LINE TABULATION', K.CONTROL, MEDIUM, ''],
  [0x000c, 'FF', 'FORM FEED', K.CONTROL, LOW, ''],
  [0x000e, 'SO', 'SHIFT OUT', K.CONTROL, MEDIUM, ''],
  [0x000f, 'SI', 'SHIFT IN', K.CONTROL, MEDIUM, ''],
  [0x001b, 'ESC', 'ESCAPE', K.ANSI, HIGH, 'Opens an ANSI escape sequence: colour, cursor movement, and text a terminal will never show you.'],
  [0x007f, 'DEL', 'DELETE', K.CONTROL, MEDIUM, ''],

  // ---- Latin-1 -----------------------------------------------------------
  [0x00a0, 'NBSP', 'NO-BREAK SPACE', K.SPACE, LOW, 'Looks exactly like a space and is not one. A classic reason copied code will not run.'],
  [0x00ad, 'SHY', 'SOFT HYPHEN', K.ZERO_WIDTH, MEDIUM, 'Invisible unless the line happens to wrap on it. Survives most copy-paste.'],

  // ---- Combining and joining ---------------------------------------------
  [0x034f, 'CGJ', 'COMBINING GRAPHEME JOINER', K.ZERO_WIDTH, MEDIUM, 'Renders as nothing, but blocks normalisation and collation from merging characters.'],
  [0x061c, 'ALM', 'ARABIC LETTER MARK', K.BIDI, MEDIUM, 'Invisible bidirectional formatting character.'],
  [0x115f, 'CHO FILLER', 'HANGUL CHOSEONG FILLER', K.ZERO_WIDTH, MEDIUM, 'Renders blank. Used to fake empty usernames and display names.'],
  [0x1160, 'JUNG FILLER', 'HANGUL JUNGSEONG FILLER', K.ZERO_WIDTH, MEDIUM, 'Renders blank.'],
  [0x17b4, 'KIVAQ', 'KHMER VOWEL INHERENT AQ', K.ZERO_WIDTH, MEDIUM, 'Renders as nothing in most fonts.'],
  [0x17b5, 'KIVAA', 'KHMER VOWEL INHERENT AA', K.ZERO_WIDTH, MEDIUM, 'Renders as nothing in most fonts.'],
  [0x180b, 'FVS1', 'MONGOLIAN FREE VARIATION SELECTOR ONE', K.VS, MEDIUM, ''],
  [0x180c, 'FVS2', 'MONGOLIAN FREE VARIATION SELECTOR TWO', K.VS, MEDIUM, ''],
  [0x180d, 'FVS3', 'MONGOLIAN FREE VARIATION SELECTOR THREE', K.VS, MEDIUM, ''],
  [0x180e, 'MVS', 'MONGOLIAN VOWEL SEPARATOR', K.ZERO_WIDTH, MEDIUM, 'Zero width since Unicode 6.3.'],

  // ---- General punctuation: spaces ---------------------------------------
  [0x2000, 'EN QUAD', 'EN QUAD', K.SPACE, LOW, ''],
  [0x2001, 'EM QUAD', 'EM QUAD', K.SPACE, LOW, ''],
  [0x2002, 'EN SP', 'EN SPACE', K.SPACE, LOW, ''],
  [0x2003, 'EM SP', 'EM SPACE', K.SPACE, LOW, ''],
  [0x2004, '3/EM SP', 'THREE-PER-EM SPACE', K.SPACE, LOW, ''],
  [0x2005, '4/EM SP', 'FOUR-PER-EM SPACE', K.SPACE, LOW, ''],
  [0x2006, '6/EM SP', 'SIX-PER-EM SPACE', K.SPACE, LOW, ''],
  [0x2007, 'FIG SP', 'FIGURE SPACE', K.SPACE, LOW, ''],
  [0x2008, 'PUNCT SP', 'PUNCTUATION SPACE', K.SPACE, LOW, ''],
  [0x2009, 'THIN SP', 'THIN SPACE', K.SPACE, LOW, ''],
  [0x200a, 'HAIR SP', 'HAIR SPACE', K.SPACE, LOW, 'Narrow enough to read as no space at all.'],

  // ---- General punctuation: the zero-width family -------------------------
  [0x200b, 'ZWSP', 'ZERO WIDTH SPACE', K.ZERO_WIDTH, HIGH, 'The workhorse of text steganography: zero width, survives copy-paste, ignored by most renderers.'],
  [0x200c, 'ZWNJ', 'ZERO WIDTH NON-JOINER', K.ZERO_WIDTH, HIGH, 'Legitimate in Persian and Indic scripts. Everywhere else it is a free invisible bit.'],
  [0x200d, 'ZWJ', 'ZERO WIDTH JOINER', K.ZERO_WIDTH, HIGH, 'Legitimate glue inside emoji sequences. Outside one, an invisible bit.'],
  [0x200e, 'LRM', 'LEFT-TO-RIGHT MARK', K.BIDI, MEDIUM, ''],
  [0x200f, 'RLM', 'RIGHT-TO-LEFT MARK', K.BIDI, MEDIUM, ''],
  [0x2028, 'LS', 'LINE SEPARATOR', K.LINEBREAK, MEDIUM, 'A newline to JavaScript, invisible to most editors.'],
  [0x2029, 'PS', 'PARAGRAPH SEPARATOR', K.LINEBREAK, MEDIUM, 'A newline to JavaScript, invisible to most editors.'],

  // ---- Bidirectional overrides: Trojan Source (CVE-2021-42574) -----------
  [0x202a, 'LRE', 'LEFT-TO-RIGHT EMBEDDING', K.BIDI, HIGH, 'Reorders the text a human reads without touching the bytes a compiler reads.'],
  [0x202b, 'RLE', 'RIGHT-TO-LEFT EMBEDDING', K.BIDI, HIGH, 'Reorders the text a human reads without touching the bytes a compiler reads.'],
  [0x202c, 'PDF', 'POP DIRECTIONAL FORMATTING', K.BIDI, HIGH, 'Closes an embedding or an override.'],
  [0x202d, 'LRO', 'LEFT-TO-RIGHT OVERRIDE', K.BIDI, CRITICAL, 'Forces display order. Half of the Trojan Source attack.'],
  [0x202e, 'RLO', 'RIGHT-TO-LEFT OVERRIDE', K.BIDI, CRITICAL, 'Forces display order. The other half of Trojan Source: source that reviews clean and compiles to something else.'],
  [0x202f, 'NNBSP', 'NARROW NO-BREAK SPACE', K.SPACE, LOW, ''],
  [0x205f, 'MMSP', 'MEDIUM MATHEMATICAL SPACE', K.SPACE, LOW, ''],

  // ---- Word joiner and the invisible operators ---------------------------
  [0x2060, 'WJ', 'WORD JOINER', K.ZERO_WIDTH, HIGH, 'Zero width with no line-break behaviour. A common third symbol in zero-width encodings.'],
  [0x2061, 'FN APP', 'FUNCTION APPLICATION', K.ZERO_WIDTH, MEDIUM, 'Invisible mathematical operator.'],
  [0x2062, 'INV TIMES', 'INVISIBLE TIMES', K.ZERO_WIDTH, MEDIUM, 'Invisible mathematical operator.'],
  [0x2063, 'INV SEP', 'INVISIBLE SEPARATOR', K.ZERO_WIDTH, MEDIUM, 'Invisible mathematical operator.'],
  [0x2064, 'INV PLUS', 'INVISIBLE PLUS', K.ZERO_WIDTH, MEDIUM, 'Invisible mathematical operator.'],

  // ---- Bidi isolates ------------------------------------------------------
  [0x2066, 'LRI', 'LEFT-TO-RIGHT ISOLATE', K.BIDI, HIGH, 'Trojan Source primitive.'],
  [0x2067, 'RLI', 'RIGHT-TO-LEFT ISOLATE', K.BIDI, HIGH, 'Trojan Source primitive.'],
  [0x2068, 'FSI', 'FIRST STRONG ISOLATE', K.BIDI, HIGH, 'Trojan Source primitive.'],
  [0x2069, 'PDI', 'POP DIRECTIONAL ISOLATE', K.BIDI, HIGH, 'Closes an isolate.'],

  // ---- Deprecated format characters --------------------------------------
  [0x206a, 'ISS', 'INHIBIT SYMMETRIC SWAPPING', K.DEPRECATED, MEDIUM, 'Deprecated by Unicode; should not appear in modern text at all.'],
  [0x206b, 'ASS', 'ACTIVATE SYMMETRIC SWAPPING', K.DEPRECATED, MEDIUM, 'Deprecated by Unicode.'],
  [0x206c, 'IAFS', 'INHIBIT ARABIC FORM SHAPING', K.DEPRECATED, MEDIUM, 'Deprecated by Unicode.'],
  [0x206d, 'AAFS', 'ACTIVATE ARABIC FORM SHAPING', K.DEPRECATED, MEDIUM, 'Deprecated by Unicode.'],
  [0x206e, 'NADS', 'NATIONAL DIGIT SHAPES', K.DEPRECATED, MEDIUM, 'Deprecated by Unicode.'],
  [0x206f, 'NODS', 'NOMINAL DIGIT SHAPES', K.DEPRECATED, MEDIUM, 'Deprecated by Unicode.'],

  // ---- CJK ---------------------------------------------------------------
  [0x3000, 'IDEO SP', 'IDEOGRAPHIC SPACE', K.SPACE, LOW, 'Full-width space. Breaks anything expecting U+0020.'],
  [0x3164, 'HANGUL FILLER', 'HANGUL FILLER', K.ZERO_WIDTH, HIGH, 'Renders as blank width. The classic "invisible username" character.'],

  // ---- Specials -----------------------------------------------------------
  [0xfeff, 'BOM', 'ZERO WIDTH NO-BREAK SPACE (BOM)', K.ZERO_WIDTH, MEDIUM, 'A byte-order mark at offset 0, an invisible character anywhere else.'],
  [0xffa0, 'HW HANGUL FILLER', 'HALFWIDTH HANGUL FILLER', K.ZERO_WIDTH, MEDIUM, 'Renders blank.'],
  [0xfff9, 'IAA', 'INTERLINEAR ANNOTATION ANCHOR', K.MARKER, HIGH, 'Opens annotated text that most renderers hide entirely.'],
  [0xfffa, 'IAS', 'INTERLINEAR ANNOTATION SEPARATOR', K.MARKER, HIGH, 'The annotation itself -- usually rendered as nothing at all.'],
  [0xfffb, 'IAT', 'INTERLINEAR ANNOTATION TERMINATOR', K.MARKER, HIGH, 'Closes an annotation.'],
  [0xfffc, 'OBJ', 'OBJECT REPLACEMENT CHARACTER', K.MARKER, LOW, 'Placeholder for an embedded object.'],
  [0xfffd, 'REPL', 'REPLACEMENT CHARACTER', K.MARKER, LOW, 'Evidence of an earlier decoding failure. The original bytes are already gone.'],

  // ---- Musical symbols that are really format characters -----------------
  [0x1d173, 'BEGIN BEAM', 'MUSICAL SYMBOL BEGIN BEAM', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],
  [0x1d174, 'END BEAM', 'MUSICAL SYMBOL END BEAM', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],
  [0x1d175, 'BEGIN TIE', 'MUSICAL SYMBOL BEGIN TIE', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],
  [0x1d176, 'END TIE', 'MUSICAL SYMBOL END TIE', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],
  [0x1d177, 'BEGIN SLUR', 'MUSICAL SYMBOL BEGIN SLUR', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],
  [0x1d178, 'END SLUR', 'MUSICAL SYMBOL END SLUR', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],
  [0x1d179, 'BEGIN PHRASE', 'MUSICAL SYMBOL BEGIN PHRASE', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],
  [0x1d17a, 'END PHRASE', 'MUSICAL SYMBOL END PHRASE', K.ZERO_WIDTH, MEDIUM, 'Default-ignorable format character.'],

  // ---- Tags block ---------------------------------------------------------
  [0xe0001, 'LANG TAG', 'LANGUAGE TAG', K.TAGS, CRITICAL, 'Deprecated tag character. Its presence means somebody reached for the Tags block deliberately.'],
  [0xe007f, 'CANCEL TAG', 'CANCEL TAG', K.TAGS, CRITICAL, 'Terminates a tag sequence -- the closing bracket of a smuggled payload.'],
];

/** Fast lookup for the individually named codepoints above. */
const NAMED = new Map();
for (const [cp, abbr, name, kind, sev, note] of TABLE) {
  NAMED.set(cp, { cp, abbr, name, kind, severity: sev, note });
}

export function hex(cp) {
  return 'U+' + cp.toString(16).toUpperCase().padStart(4, '0');
}

const ASCII_PUNCT_NAMES = {
  0x20: 'SPACE', 0x21: 'EXCLAMATION MARK', 0x22: 'QUOTATION MARK',
  0x23: 'NUMBER SIGN', 0x24: 'DOLLAR SIGN', 0x25: 'PERCENT SIGN',
  0x26: 'AMPERSAND', 0x27: 'APOSTROPHE', 0x2e: 'FULL STOP',
  0x2f: 'SOLIDUS', 0x3a: 'COLON', 0x3b: 'SEMICOLON',
  0x3c: 'LESS-THAN SIGN', 0x3e: 'GREATER-THAN SIGN', 0x5c: 'REVERSE SOLIDUS',
  0x7e: 'TILDE',
};

function asciiName(code) {
  if (ASCII_PUNCT_NAMES[code]) return ASCII_PUNCT_NAMES[code];
  const ch = String.fromCharCode(code);
  if (/[A-Za-z]/.test(ch)) return 'LATIN LETTER ' + ch;
  if (/[0-9]/.test(ch)) return 'DIGIT ' + ch;
  return "'" + ch + "'";
}

/**
 * Ranges checked after the named table. Order matters: first match wins, so
 * the narrow Tags sub-range sits above the broad one.
 */
const RANGES = [
  {
    lo: 0x0080, hi: 0x009f, kind: K.CONTROL, severity: MEDIUM,
    label: (cp) => ['C1-' + hex(cp).slice(2), 'C1 CONTROL ' + hex(cp)],
    note: 'C1 control character. Almost always the residue of a mis-decoded byte stream.',
  },
  {
    // VARIATION SELECTOR-1 .. 16
    lo: 0xfe00, hi: 0xfe0f, kind: K.VS, severity: HIGH,
    label: (cp) => {
      const n = cp - 0xfe00 + 1;
      return ['VS-' + n, 'VARIATION SELECTOR-' + n];
    },
    note: 'Selects a glyph variant. VS-16 straight after an emoji is normal; a run of them is a byte stream.',
  },
  {
    // VARIATION SELECTOR-17 .. 256 -- the emoji steganography channel
    lo: 0xe0100, hi: 0xe01ef, kind: K.VS, severity: CRITICAL,
    label: (cp) => {
      const n = cp - 0xe0100 + 17;
      return ['VS-' + n, 'VARIATION SELECTOR-' + n];
    },
    note: 'Supplementary variation selector: 240 invisible codepoints that map cleanly onto byte values.',
  },
  {
    // Tags block -- a shadow copy of printable ASCII that renders as nothing
    lo: 0xe0020, hi: 0xe007e, kind: K.TAGS, severity: CRITICAL,
    label: (cp) => {
      const code = cp - 0xe0000;
      const ch = String.fromCharCode(code);
      return ['TAG ' + (code === 0x20 ? 'SP' : ch), 'TAG ' + asciiName(code)];
    },
    note: 'Tags block: U+E0000 plus an ASCII code. Invisible everywhere, still plain text to a tokenizer.',
  },
  {
    lo: 0xe0000, hi: 0xe007f, kind: K.TAGS, severity: CRITICAL,
    label: (cp) => ['TAG ' + hex(cp), 'TAG CHARACTER ' + hex(cp)],
    note: 'Tags block.',
  },
  {
    lo: 0xfdd0, hi: 0xfdef, kind: K.NONCHAR, severity: HIGH,
    label: (cp) => ['NONCHAR', 'NONCHARACTER ' + hex(cp)],
    note: 'Permanently reserved as a non-character. Valid input to nothing.',
  },
  {
    lo: 0xe000, hi: 0xf8ff, kind: K.PUA, severity: MEDIUM,
    label: (cp) => ['PUA', 'PRIVATE USE ' + hex(cp)],
    note: 'Private Use Area. Its meaning depends entirely on a font you probably do not have.',
  },
  {
    lo: 0xf0000, hi: 0xffffd, kind: K.PUA, severity: MEDIUM,
    label: (cp) => ['PUA-A', 'SUPPLEMENTARY PRIVATE USE ' + hex(cp)],
    note: 'Supplementary Private Use Area-A.',
  },
  {
    lo: 0x100000, hi: 0x10fffd, kind: K.PUA, severity: MEDIUM,
    label: (cp) => ['PUA-B', 'SUPPLEMENTARY PRIVATE USE ' + hex(cp)],
    note: 'Supplementary Private Use Area-B.',
  },
];

/** True for codepoints Unicode reserves permanently as non-characters. */
export function isNoncharacter(cp) {
  if (cp >= 0xfdd0 && cp <= 0xfdef) return true;
  const low = cp & 0xffff;
  return low === 0xfffe || low === 0xffff;
}

/**
 * Describe a codepoint, or return null when it is unremarkable.
 *
 * Tab, line feed and carriage return are deliberately not flagged: they are
 * ordinary text. detect.js checks line-ending consistency separately.
 */
export function describe(cp) {
  const named = NAMED.get(cp);
  if (named) return named;

  if (isNoncharacter(cp)) {
    return {
      cp, abbr: 'NONCHAR', name: 'NONCHARACTER ' + hex(cp),
      kind: K.NONCHAR, severity: HIGH,
      note: 'Permanently reserved as a non-character.',
    };
  }

  for (const r of RANGES) {
    if (cp >= r.lo && cp <= r.hi) {
      const [abbr, name] = r.label(cp);
      return { cp, abbr, name, kind: r.kind, severity: r.severity, note: r.note };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Confusables
// ---------------------------------------------------------------------------

/**
 * Characters from another writing system drawn the same as a Latin letter,
 * digit or punctuation mark.
 *
 * Compatibility lookalikes -- full-width Latin, the mathematical alphanumeric
 * blocks, circled and parenthesised letters -- are deliberately absent. NFKC
 * already folds all of those to ASCII, so detect.js finds them by normalising
 * instead of by lookup. That single rule covers about a thousand codepoints
 * this table would otherwise have to enumerate.
 *
 * [codepoint, ASCII lookalike, source script]
 */
const CONFUSABLE_TABLE = [
  // ---- Cyrillic ----------------------------------------------------------
  [0x0430, 'a', 'Cyrillic'], [0x0435, 'e', 'Cyrillic'], [0x043e, 'o', 'Cyrillic'],
  [0x0440, 'p', 'Cyrillic'], [0x0441, 'c', 'Cyrillic'], [0x0443, 'y', 'Cyrillic'],
  [0x0445, 'x', 'Cyrillic'], [0x0455, 's', 'Cyrillic'], [0x0456, 'i', 'Cyrillic'],
  [0x0458, 'j', 'Cyrillic'], [0x04bb, 'h', 'Cyrillic'], [0x0501, 'd', 'Cyrillic'],
  [0x04cf, 'l', 'Cyrillic'],
  [0x0410, 'A', 'Cyrillic'], [0x0412, 'B', 'Cyrillic'], [0x0415, 'E', 'Cyrillic'],
  [0x041a, 'K', 'Cyrillic'], [0x041c, 'M', 'Cyrillic'], [0x041d, 'H', 'Cyrillic'],
  [0x041e, 'O', 'Cyrillic'], [0x0420, 'P', 'Cyrillic'], [0x0421, 'C', 'Cyrillic'],
  [0x0422, 'T', 'Cyrillic'], [0x0423, 'Y', 'Cyrillic'], [0x0425, 'X', 'Cyrillic'],
  [0x0405, 'S', 'Cyrillic'], [0x0406, 'I', 'Cyrillic'], [0x0408, 'J', 'Cyrillic'],
  [0x0500, 'D', 'Cyrillic'], [0x04ae, 'Y', 'Cyrillic'], [0x04c0, 'I', 'Cyrillic'],

  // ---- Greek -------------------------------------------------------------
  [0x03bf, 'o', 'Greek'], [0x03bd, 'v', 'Greek'], [0x03c1, 'p', 'Greek'],
  [0x03c4, 't', 'Greek'], [0x03c5, 'u', 'Greek'], [0x03c7, 'x', 'Greek'],
  [0x03b1, 'a', 'Greek'], [0x03b9, 'i', 'Greek'], [0x03ba, 'k', 'Greek'],
  [0x03b3, 'y', 'Greek'], [0x03b5, 'e', 'Greek'],
  [0x0391, 'A', 'Greek'], [0x0392, 'B', 'Greek'], [0x0395, 'E', 'Greek'],
  [0x0396, 'Z', 'Greek'], [0x0397, 'H', 'Greek'], [0x0399, 'I', 'Greek'],
  [0x039a, 'K', 'Greek'], [0x039c, 'M', 'Greek'], [0x039d, 'N', 'Greek'],
  [0x039f, 'O', 'Greek'], [0x03a1, 'P', 'Greek'], [0x03a4, 'T', 'Greek'],
  [0x03a5, 'Y', 'Greek'], [0x03a7, 'X', 'Greek'], [0x03f9, 'C', 'Greek'],
  [0x03fa, 'M', 'Greek'],
  [0x037e, ';', 'Greek'],   // GREEK QUESTION MARK: identical to a semicolon

  // ---- Armenian ----------------------------------------------------------
  [0x0585, 'o', 'Armenian'], [0x0578, 'n', 'Armenian'], [0x057d, 'u', 'Armenian'],
  [0x0566, 'q', 'Armenian'], [0x0570, 'h', 'Armenian'], [0x0561, 'w', 'Armenian'],
  [0x0584, 'p', 'Armenian'], [0x0563, 'q', 'Armenian'], [0x0555, 'O', 'Armenian'],
  [0x0589, ':', 'Armenian'],

  // ---- Cherokee ----------------------------------------------------------
  [0x13a0, 'D', 'Cherokee'], [0x13a1, 'R', 'Cherokee'], [0x13a2, 'T', 'Cherokee'],
  [0x13aa, 'A', 'Cherokee'], [0x13ab, 'J', 'Cherokee'], [0x13ac, 'E', 'Cherokee'],
  [0x13b3, 'W', 'Cherokee'], [0x13bb, 'H', 'Cherokee'], [0x13c0, 'G', 'Cherokee'],
  [0x13c3, 'Z', 'Cherokee'], [0x13d2, 'R', 'Cherokee'], [0x13da, 'S', 'Cherokee'],
  [0x13df, 'C', 'Cherokee'], [0x13e2, 'P', 'Cherokee'], [0x13e6, 'K', 'Cherokee'],
  [0x13f4, 'B', 'Cherokee'],

  // ---- Coptic and Lisu ---------------------------------------------------
  [0x2c9e, 'O', 'Coptic'], [0x2c92, 'I', 'Coptic'], [0x2c98, 'M', 'Coptic'],
  [0xa4d0, 'T', 'Lisu'], [0xa4f4, 'L', 'Lisu'], [0xa4e8, 'X', 'Lisu'],

  // ---- Digits ------------------------------------------------------------
  [0x0664, '4', 'Arabic'], [0x06f4, '4', 'Arabic'], [0x07c1, '1', 'NKo'],

  // ---- Punctuation that will not compile ---------------------------------
  [0x01c0, 'l', 'Latin'],
  [0x2044, '/', 'Common'], [0x2215, '/', 'Common'], [0x29f8, '/', 'Common'],
  [0x2010, '-', 'Common'], [0x2011, '-', 'Common'], [0x2012, '-', 'Common'],
  [0x2013, '-', 'Common'], [0x2014, '-', 'Common'], [0x2212, '-', 'Common'],
  [0x02d7, '-', 'Common'],
  [0x2018, "'", 'Common'], [0x2019, "'", 'Common'], [0x201a, "'", 'Common'],
  [0x201b, "'", 'Common'], [0x2032, "'", 'Common'], [0x02b9, "'", 'Common'],
  [0x201c, '"', 'Common'], [0x201d, '"', 'Common'], [0x201e, '"', 'Common'],
  [0x2033, '"', 'Common'],
  [0x05c3, ':', 'Hebrew'], [0x2236, ':', 'Common'],
  [0x060c, ',', 'Arabic'], [0x066b, ',', 'Arabic'],
  [0x2024, '.', 'Common'], [0x06d4, '.', 'Arabic'], [0x0701, '.', 'Syriac'],
  [0x2e2e, '?', 'Common'], [0x061f, '?', 'Arabic'],
];

/** codepoint -> { to, script } */
export const CONFUSABLES = new Map(
  CONFUSABLE_TABLE.map(([cp, to, script]) => [cp, { to, script }]),
);

/**
 * Scripts treated as homoglyph carriers when they turn up inside an otherwise
 * Latin word.
 *
 * Hangul, Han, Hiragana and Katakana are deliberately absent. Mixing those
 * with Latin in a single token is ordinary Korean, Japanese and Chinese text,
 * not an attack, and flagging it would make the tool useless to most of the
 * people who need it.
 */
export const HOMOGLYPH_SCRIPTS = [
  ['Cyrillic', /\p{Script=Cyrillic}/u],
  ['Greek', /\p{Script=Greek}/u],
  ['Armenian', /\p{Script=Armenian}/u],
  ['Cherokee', /\p{Script=Cherokee}/u],
  ['Coptic', /\p{Script=Coptic}/u],
  ['Lisu', /\p{Script=Lisu}/u],
  ['Osage', /\p{Script=Osage}/u],
  ['Deseret', /\p{Script=Deseret}/u],
  ['Arabic', /\p{Script=Arabic}/u],
  ['Hebrew', /\p{Script=Hebrew}/u],
];

export const LATIN_RE = /\p{Script=Latin}/u;
