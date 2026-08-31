/**
 * secondsight -- copy comparison
 *
 * Two people were sent the same document. One of them leaked it. If the sender
 * tagged each copy with invisible characters -- and document trackers, mail
 * gateways and "AI humanizer" tools all do -- then the two files read
 * identically, diff identically in every tool that strips them, and are not the
 * same file at all.
 *
 * This module answers the only question that matters in that situation: do
 * these two copies differ, and if so, where, and what does the difference say?
 *
 * It is deliberately not a general diff. A general diff over codepoints would
 * drown the one signal worth seeing in a thousand words of legitimate edit.
 * Instead the visible text is compared as a whole, the invisible marks are
 * anchored to the visible character they trail, and only the marks are aligned.
 *
 * Zero dependencies. Pure ASCII source.
 */

import { analyze, visibleText } from './detect.js';

/**
 * A stable short id for a copy's invisible payload.
 *
 * FNV-1a, 32 bits, over the hidden codepoints in order. It is a label, not a
 * cryptographic commitment: two copies with the same id carry the same marks,
 * which is the whole claim being made.
 */
export function fingerprint(codepoints) {
  let h = 0x811c9dc5;
  for (const cp of codepoints) {
    h ^= cp & 0xff; h = Math.imul(h, 0x01000193);
    h ^= (cp >>> 8) & 0xff; h = Math.imul(h, 0x01000193);
    h ^= (cp >>> 16) & 0xff; h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

/**
 * Group a copy's hidden characters into runs, each anchored to the number of
 * visible characters that precede it.
 *
 * Anchoring on the visible index rather than the raw offset is what makes two
 * copies comparable: the mark that sits after the fortieth visible character
 * is the same mark in both files, however many invisible ones came before it.
 * Characters the engine decided are doing their job -- emoji joiners, a Persian
 * ZWNJ, a leading byte-order mark -- are not marks and are skipped.
 */
export function marksOf(result) {
  const marks = [];
  let visibleIndex = 0;
  let visible = '';
  let run = null;

  for (const cell of result.cells) {
    if (cell.hidden && !cell.benign) {
      if (!run) {
        run = { at: visibleIndex, context: visible.slice(-28), cps: [], abbrs: [] };
        marks.push(run);
      }
      run.cps.push(cell.cp);
      run.abbrs.push(cell.info ? cell.info.abbr : 'U+' + cell.cp.toString(16).toUpperCase());
    } else {
      run = null;
      visibleIndex++;
      visible += cell.ch;
    }
  }
  return marks;
}

/** Everything worth knowing about one copy on its own. */
function describeCopy(label, text) {
  const result = analyze(text);
  const marks = marksOf(result);
  const cps = marks.flatMap((m) => m.cps);
  return {
    label,
    text,
    result,
    visible: visibleText(result),
    marks,
    hidden: cps.length,
    signature: cps.length ? fingerprint(cps) : null,
    payloads: result.findings
      .filter((f) => f.decoded)
      .map((f) => ({ id: f.id, title: f.title, decoded: f.decoded, scheme: f.scheme || null })),
  };
}

const key = (m) => m.cps.join(',');

/**
 * The index of the first mark in a pair of runs that is not the same.
 *
 * Two watermarked copies usually share a long identical prefix -- the header
 * bits of a serial number, the same field names -- so printing a run from its
 * start shows two identical columns and proves nothing. This is where the
 * columns actually part company, and it is what the report should point at.
 */
function firstDivergence(a, b) {
  const ca = a ? a.cps : [];
  const cb = b ? b.cps : [];
  const n = Math.max(ca.length, cb.length);
  for (let i = 0; i < n; i++) if (ca[i] !== cb[i]) return i;
  return 0;
}

/**
 * Compare two copies of what is meant to be the same document.
 *
 * `relation` is the headline finding and is one of:
 *   'empty'    -- there is nothing to compare yet
 *   'identical'-- the same bytes; nothing distinguishes these copies
 *   'marked'   -- identical to a reader, different to a machine. The case this
 *                 module exists for: the difference is a fingerprint
 *   'edited'   -- the visible text differs, so an ordinary diff already sees it
 */
export function compare(textA, textB) {
  const a = describeCopy('A', String(textA ?? ''));
  const b = describeCopy('B', String(textB ?? ''));

  const sameBytes = a.text === b.text;
  const sameVisible = a.visible === b.visible;

  const byAnchor = new Map();
  for (const m of a.marks) byAnchor.set(m.at, { at: m.at, context: m.context, a: m, b: null });
  for (const m of b.marks) {
    const row = byAnchor.get(m.at);
    if (row) row.b = m;
    else byAnchor.set(m.at, { at: m.at, context: m.context, a: null, b: m });
  }

  const differences = [...byAnchor.values()]
    .filter((row) => key(row.a || { cps: [] }) !== key(row.b || { cps: [] }))
    .sort((x, y) => x.at - y.at)
    .map((row) => ({ ...row, divergeAt: firstDivergence(row.a, row.b) }));

  const differingCodepoints = differences.reduce(
    (n, row) => n + Math.max(row.a ? row.a.cps.length : 0, row.b ? row.b.cps.length : 0),
    0,
  );

  let relation = 'marked';
  if (!a.text && !b.text) relation = 'empty';
  else if (sameBytes) relation = 'identical';
  else if (!sameVisible) relation = 'edited';
  else if (!differences.length) relation = 'identical';

  return {
    relation,
    sameBytes,
    sameVisible,
    copies: [a, b],
    differences,
    differingCodepoints,
    headline: HEADLINE[relation],
    detail: detailFor(relation, a, b, differences, differingCodepoints),
  };
}

const HEADLINE = {
  empty: 'Nothing to compare yet',
  identical: 'The same document, twice',
  marked: 'Same to you. Not the same to a machine.',
  edited: 'These are different documents',
};

function plural(n, word) {
  return n + ' ' + word + (n === 1 ? '' : 's');
}

function detailFor(relation, a, b, differences, differingCodepoints) {
  if (relation === 'empty') return 'Paste a copy into each side.';

  if (relation === 'identical') {
    return a.hidden || b.hidden
      ? 'Byte for byte the same, invisible characters included. Both copies carry the '
        + 'same ' + plural(a.hidden, 'hidden character') + ', so nothing here distinguishes '
        + 'one recipient from another.'
      : 'Byte for byte the same, and neither copy carries a hidden character.';
  }

  if (relation === 'edited') {
    return 'The visible text is not the same, so an ordinary diff already shows you the '
      + 'difference. Comparing invisible marks only tells you something once the words '
      + 'match -- fix the visible drift first, or compare the version each recipient '
      + 'actually received.';
  }

  return 'Every visible character is identical, so no diff, no search and no pair of eyes '
    + 'will separate these two files. They differ in ' + plural(differingCodepoints, 'invisible character')
    + ' across ' + plural(differences.length, 'position') + '. That difference is not an '
    + 'accident of editing -- it is what a per-copy watermark looks like from the outside.';
}

/**
 * A one-line rendering of a run of marks, windowed on the interesting part.
 *
 * `from` is where the two copies stop agreeing, so the window opens a couple of
 * marks earlier: seeing the last matching pair next to the first mismatched one
 * is what makes the difference readable rather than merely asserted.
 */
export function markSummary(mark, limit = 10, from = 0) {
  if (!mark || !mark.abbrs.length) return '(nothing)';
  const start = Math.max(0, Math.min(from - 2, mark.abbrs.length - limit));
  const shown = mark.abbrs.slice(start, start + limit).join(' ');
  return (start > 0 ? '... ' : '')
    + shown
    + (start + limit < mark.abbrs.length ? ' ...' : '')
    + '  [' + mark.abbrs.length + ']';
}
