/**
 * secondsight -- SARIF output
 *
 * SARIF 2.1.0 is the format GitHub code scanning ingests. Emit it, upload it
 * with github/codeql-action/upload-sarif, and every finding shows up as an
 * annotation on the pull request and an alert in the Security tab.
 *
 * This module is pure and does no I/O, so the CLI, a build script and the test
 * suite all share one implementation. Pure ASCII source.
 */

// INFO, LOW, MEDIUM, HIGH, CRITICAL -> SARIF level.
const LEVEL = ['note', 'note', 'warning', 'error', 'error'];

// GitHub reads `security-severity` (0.0-10.0) to bucket alerts in the UI.
const SECURITY_SEVERITY = ['1.0', '3.0', '5.0', '8.0', '9.5'];

const HELP_URI = 'https://github.com/jinwovo/secondsight#what-it-looks-for';
const INFO_URI = 'https://github.com/jinwovo/secondsight';

/** Byte offsets where each line begins, for offset -> line/column mapping. */
function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

/** UTF-16 offset -> 1-based { line, column }, matching SARIF's default columnKind. */
function offsetToLineCol(starts, offset) {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid;
    else hi = mid - 1;
  }
  return { line: lo + 1, column: offset - starts[lo] + 1 };
}

/** kebab-case finding id -> PascalCase SARIF rule name. */
function ruleName(id) {
  return id.split(/[^a-z0-9]+/i)
    .filter(Boolean)
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join('');
}

function clamp(text, max) {
  const s = String(text).replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 3) + '...' : s;
}

/**
 * Build a SARIF 2.1.0 log from analyzer reports.
 *
 * @param {Array<{path: string, result: object}>} reports
 *        Each result is the object returned by analyze(); result.text is the
 *        scanned content, used to turn codepoint offsets into line/column.
 * @param {{version?: string}} [opts]
 */
export function buildSarif(reports, opts = {}) {
  const rules = new Map();
  const results = [];

  for (const { path, result } of reports) {
    const uri = String(path).replace(/\\/g, '/');
    const starts = lineStarts(result.text || '');

    for (const f of result.findings) {
      if (!rules.has(f.id)) {
        rules.set(f.id, {
          id: f.id,
          name: ruleName(f.id),
          shortDescription: { text: f.title },
          fullDescription: { text: clamp(f.detail || f.title, 900) },
          helpUri: HELP_URI,
          defaultConfiguration: { level: LEVEL[f.severity] },
          properties: {
            tags: ['security', 'unicode'],
            'security-severity': SECURITY_SEVERITY[f.severity],
          },
        });
      }

      const offset = f.positions && f.positions.length ? f.positions[0] : 0;
      const { line, column } = offsetToLineCol(starts, offset);

      const parts = [f.title];
      if (f.count > 1) parts.push('x' + f.count);
      if (f.decoded) parts.push('Decoded: "' + clamp(f.decoded, 200) + '"');
      if (f.intents && f.intents.length) {
        parts.push('reads as ' + f.intents.map((i) => i.label).join(', '));
      }
      if (f.reference) parts.push('(' + f.reference + ')');

      results.push({
        ruleId: f.id,
        level: LEVEL[f.severity],
        message: { text: parts.join(' -- ') },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri },
            region: { startLine: line, startColumn: column, endColumn: column + 1 },
          },
        }],
        partialFingerprints: {
          secondsight: f.id + ':' + uri + ':' + line + ':' + column,
        },
      });
    }
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'secondsight',
          informationUri: INFO_URI,
          version: opts.version || '0.0.0',
          rules: [...rules.values()],
        },
      },
      columnKind: 'utf16CodeUnits',
      results,
    }],
  };
}
