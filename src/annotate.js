/**
 * secondsight -- GitHub Actions annotations
 *
 * A failed check that says "3 files have findings" sends a reviewer to the
 * log. An annotation puts the finding on the line of the pull request where it
 * is, with no SARIF upload and no permissions to grant. The CLI writes these
 * whenever it runs inside GitHub Actions.
 *
 * Every message here carries text an attacker wrote -- that is what a decoded
 * payload is. A workflow command is a line of log output that starts with
 * `::`, so a payload that could put a newline into this output could issue
 * commands of its own. Every value is escaped the way the runner unescapes
 * it, and nothing attacker-controlled is written anywhere else on the line.
 *
 * Zero dependencies. Pure ASCII source.
 */

import { SEVERITY } from './detect.js';

// INFO, LOW -> notice; MEDIUM -> warning; HIGH, CRITICAL -> error
const COMMAND = ['notice', 'notice', 'warning', 'error', 'error'];

/** Escaping for the message, as the runner defines it. */
function escapeData(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/** Property values also lose `:` and `,`, which delimit the properties. */
function escapeProperty(s) {
  return escapeData(s).replace(/:/g, '%3A').replace(/,/g, '%2C');
}

function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text.charCodeAt(i) === 10) starts.push(i + 1);
  }
  return starts;
}

/** UTF-16 offset -> 1-based line and column, the units findings are reported in. */
function locate(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, col: offset - starts[lo] + 1 };
}

function oneLine(s, max) {
  const flat = String(s).replace(/\s+/g, ' ').trim();
  return flat.length > max ? flat.slice(0, max - 3) + '...' : flat;
}

/**
 * Workflow commands for every finding, one per finding at its first position.
 *
 * @param {Array<{path: string, result: object}>} reports  path relative to the workspace
 * @returns {string} lines to write to stdout, each ending in a newline
 */
export function buildAnnotations(reports) {
  let out = '';
  for (const { path, result } of reports) {
    if (!result.findings.length) continue;
    const starts = lineStarts(result.text || '');
    const file = String(path).replace(/\\/g, '/');
    for (const f of result.findings) {
      const { line, col } = locate(starts, f.positions && f.positions.length ? f.positions[0] : 0);
      const parts = [f.title + (f.count > 1 ? ' (x' + f.count + ')' : '')];
      if (f.decoded) parts.push('decoded: ' + JSON.stringify(oneLine(f.decoded, 200)));
      if (f.intents && f.intents.length) parts.push('reads as: ' + f.intents.map((i) => i.label).join(', '));
      if (f.samples && f.samples.length) parts.push(oneLine(f.samples.slice(0, 3).join('  '), 160));
      out += '::' + COMMAND[f.severity]
        + ' file=' + escapeProperty(file)
        + ',line=' + line + ',col=' + col
        + ',title=' + escapeProperty('secondsight ' + SEVERITY[f.severity] + ': ' + f.id)
        + '::' + escapeData(parts.join(' -- ')) + '\n';
    }
  }
  return out;
}
