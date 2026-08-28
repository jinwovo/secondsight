/**
 * secondsight -- sanitizer
 *
 * Removing characters from someone's text is a destructive act, so every rule
 * here is opt-in, each one reports exactly what it changed, and none of them
 * touch a character the engine decided was doing its job. Stripping the joiner
 * out of an emoji or the ZWNJ out of a Persian word would be a bug, not a fix.
 *
 * Zero dependencies. Pure ASCII source.
 */

import { KIND } from './catalog.js';
import { analyze } from './detect.js';
import { findAnsiSequences } from './decode.js';

export const DEFAULT_OPTIONS = {
  stripHidden: true,        // zero-width, tags, variation selectors, bidi, controls
  stripAnsi: true,          // ANSI escape sequences
  normalizeSpaces: true,    // every exotic space becomes U+0020
  foldConfusables: false,   // lookalike letters become their ASCII twin
  normalize: 'NFC',         // 'none' | 'NFC' | 'NFKC'
};

const STRIPPABLE = new Set([
  KIND.ZERO_WIDTH, KIND.TAGS, KIND.VS, KIND.BIDI,
  KIND.CONTROL, KIND.DEPRECATED, KIND.MARKER, KIND.NONCHAR,
]);

/**
 * Clean a string.
 *
 * Returns the result plus a ledger of what was done, because a sanitizer that
 * silently rewrites text is only marginally better than the text it fixed.
 */
export function sanitize(text, options = {}) {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  const result = analyze(text);
  const changes = [];
  const bump = (label) => {
    const found = changes.find((c) => c.label === label);
    if (found) found.count++;
    else changes.push({ label, count: 1 });
  };

  let out = '';
  for (const cell of result.cells) {
    // Never touch a character that is doing its actual job.
    if (cell.benign) { out += cell.ch; continue; }

    if (opts.stripHidden && cell.info && STRIPPABLE.has(cell.info.kind)) {
      // Tab, newline and carriage return are ordinary text.
      if (cell.cp === 0x09 || cell.cp === 0x0a || cell.cp === 0x0d) { out += cell.ch; continue; }
      bump('removed ' + cell.info.abbr);
      continue;
    }

    if (opts.normalizeSpaces && cell.info && cell.info.kind === KIND.SPACE) {
      bump('replaced ' + cell.info.abbr + ' with a space');
      out += ' ';
      continue;
    }

    if (opts.stripHidden && cell.info && cell.info.kind === KIND.LINEBREAK) {
      bump('replaced ' + cell.info.abbr + ' with a newline');
      out += '\n';
      continue;
    }

    if (opts.foldConfusables && cell.confusable) {
      bump('folded ' + cell.confusable.script + ' lookalike to "' + cell.confusable.to + '"');
      out += cell.confusable.to;
      continue;
    }

    out += cell.ch;
  }

  if (opts.stripAnsi) {
    const before = out;
    // Re-scan the already-stripped text: removing ESC above leaves the visible
    // remainder of a sequence behind, and that remainder is still noise.
    const seqs = findAnsiSequences(before);
    if (seqs.length) {
      let rebuilt = '';
      let cursor = 0;
      for (const s of seqs) {
        rebuilt += before.slice(cursor, s.index);
        cursor = s.index + s.raw.length;
      }
      rebuilt += before.slice(cursor);
      out = rebuilt;
      bump('removed ' + seqs.length + ' ANSI escape sequence' + (seqs.length === 1 ? '' : 's'));
    }
    // Orphaned CSI bodies left behind once their ESC was stripped as a control.
    const orphans = out.match(/\[[0-9;?]{0,8}[A-Za-z]/g);
    if (opts.stripHidden && orphans && result.findings.some((f) => f.id === 'ansi-escapes')) {
      out = out.replace(/\[[0-9;?]{0,8}[A-Za-z]/g, '');
      bump('removed ' + orphans.length + ' orphaned escape body');
    }
  }

  if (opts.normalize && opts.normalize !== 'none') {
    const normalized = out.normalize(opts.normalize);
    if (normalized !== out) {
      bump('normalised to ' + opts.normalize);
      out = normalized;
    }
  }

  return {
    text: out,
    changes,
    removed: [...text].length - [...out].length,
    clean: analyze(out).verdict.severity < 0,
  };
}
