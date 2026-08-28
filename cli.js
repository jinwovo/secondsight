#!/usr/bin/env node
/**
 * secondsight -- command line
 *
 *   npx github:jinwovo/secondsight README.md
 *   cat suspicious.txt | npx github:jinwovo/secondsight
 *   npx github:jinwovo/secondsight . --fail-on high      # for CI
 *
 * Same engine as the web page, no network, no dependencies.
 */

import { readFileSync, writeFileSync, statSync, readdirSync } from 'node:fs';
import { join, relative, extname, basename } from 'node:path';
import { analyze, SEVERITY } from './src/detect.js';
import { sanitize } from './src/sanitize.js';
import { buildSarif } from './src/sarif.js';

const VERSION = '1.2.0';

const USAGE = `
secondsight -- find the text you cannot see

  secondsight [options] [file|directory ...]

  With no path, reads standard input.

Options
  --json             machine-readable output
  --sarif [file]     SARIF 2.1.0 for GitHub code scanning (stdout, or to <file>)
  --fix              rewrite files with hidden characters removed
  --fail-on <level>  exit 1 at or above this severity
                     (info|low|medium|high|critical; default: high)
  --all              report every file, not just the ones with findings
  --no-color         plain output
  -h, --help         this
`;

// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const opts = {
  json: false, sarif: false, sarifPath: null,
  fix: false, all: false, color: true,
  failOn: 3, failOnExplicit: false, paths: [],
};

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--json') opts.json = true;
  else if (a === '--sarif') {
    opts.sarif = true;
    // Optional filename: the next arg, unless it is another flag or a path
    // that exists (which would be a scan target, not the output file).
    const next = args[i + 1];
    if (next && !next.startsWith('-') && !existsAsPath(next)) {
      opts.sarifPath = next;
      i++;
    }
  } else if (a === '--fix') opts.fix = true;
  else if (a === '--all') opts.all = true;
  else if (a === '--no-color') opts.color = false;
  else if (a === '--fail-on') {
    const level = String(args[++i] || '').toUpperCase();
    const idx = SEVERITY.indexOf(level);
    if (idx < 0) { fail('unknown severity: ' + level); }
    opts.failOn = idx;
    opts.failOnExplicit = true;
  } else if (a === '-h' || a === '--help') { process.stdout.write(USAGE); process.exit(0); }
  else if (a === '--version' || a === '-v') { process.stdout.write(VERSION + '\n'); process.exit(0); }
  else if (a.startsWith('-')) fail('unknown option: ' + a);
  else opts.paths.push(a);
}

function existsAsPath(p) {
  try { statSync(p); return true; } catch { return false; }
}

function fail(message) {
  process.stderr.write('secondsight: ' + message + '\n' + USAGE);
  process.exit(2);
}

// ---------------------------------------------------------------------------

const useColor = opts.color && process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code, s) => (useColor ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s);
const dim = (s) => paint('2', s);
const bold = (s) => paint('1', s);
const SEVERITY_COLOR = ['2', '2', '33', '31', '1;31'];

// Files an agent, a build or a reviewer is likely to read as text.
const TEXT_EXTENSIONS = new Set([
  '.md', '.markdown', '.txt', '.json', '.jsonc', '.yaml', '.yml', '.toml', '.ini',
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.rb', '.go', '.rs',
  '.java', '.kt', '.c', '.h', '.cc', '.cpp', '.cs', '.php', '.sh', '.bash', '.zsh',
  '.html', '.css', '.scss', '.sql', '.graphql', '.env', '.cfg', '.conf', '.xml',
]);
const ALWAYS_READ = new Set([
  'CLAUDE.md', 'AGENTS.md', 'SKILL.md', 'README.md', 'Dockerfile', 'Makefile',
  '.cursorrules', '.gitattributes', '.npmrc',
]);
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'vendor', 'target',
  '.next', '.venv', '__pycache__', 'coverage',
]);

function collect(path, out = []) {
  let st;
  try { st = statSync(path); } catch { fail('cannot read ' + path); }
  if (st.isDirectory()) {
    if (SKIP_DIRS.has(basename(path))) return out;
    for (const entry of readdirSync(path)) collect(join(path, entry), out);
    return out;
  }
  if (st.size > 8 * 1024 * 1024) return out;
  if (ALWAYS_READ.has(basename(path)) || TEXT_EXTENSIONS.has(extname(path).toLowerCase())) {
    out.push(path);
  }
  return out;
}

function readStdin() {
  try { return readFileSync(0, 'utf8'); } catch { return ''; }
}

// ---------------------------------------------------------------------------

function reportText(label, result) {
  const sev = result.verdict.severity;
  if (sev < 0 && !opts.all) return;

  const tag = sev < 0 ? paint('32', 'CLEAN') : paint(SEVERITY_COLOR[sev], result.verdict.label);
  process.stdout.write('\n' + bold(label) + '  ' + tag + '\n');
  if (sev < 0) return;

  process.stdout.write(dim('  ' + result.verdict.line) + '\n');
  process.stdout.write(dim(
    '  ' + result.stats.visible + ' visible, ' + result.stats.hidden + ' hidden'
    + (result.stats.benignHidden ? ', ' + result.stats.benignHidden + ' expected' : '')
    + ' (' + result.stats.codepoints + ' codepoints)',
  ) + '\n');

  for (const f of result.findings) {
    const level = SEVERITY[f.severity].padEnd(10);
    process.stdout.write(
      '  ' + paint(SEVERITY_COLOR[f.severity], level) + f.title
      + dim('  x' + f.count) + '\n',
    );
    if (f.decoded) {
      const preview = f.decoded.replace(/\s+/g, ' ').slice(0, 160);
      process.stdout.write('           ' + paint('36', 'decoded: ') + JSON.stringify(preview) + '\n');
    }
    if (f.intents.length) {
      process.stdout.write('           ' + dim('reads as: ' + f.intents.map((i) => i.label).join(', ')) + '\n');
    }
    if (f.samples.length) {
      process.stdout.write('           ' + dim(f.samples.slice(0, 4).join('  ')) + '\n');
    }
    if (f.reference) {
      process.stdout.write('           ' + dim(f.reference) + '\n');
    }
  }
}

// ---------------------------------------------------------------------------

const targets = opts.paths.flatMap((p) => collect(p));
const reports = [];
let worst = -1;

if (!opts.paths.length) {
  const text = readStdin();
  const result = analyze(text);
  worst = result.verdict.severity;
  reports.push({ path: '<stdin>', result });
  if (!opts.json && !opts.sarif) reportText('<stdin>', result);
} else {
  for (const path of targets) {
    let text;
    try { text = readFileSync(path, 'utf8'); } catch { continue; }
    const result = analyze(text);
    worst = Math.max(worst, result.verdict.severity);
    reports.push({ path, result });
    if (!opts.json && !opts.sarif) reportText(relative(process.cwd(), path) || path, result);

    if (opts.fix && result.verdict.severity >= 0) {
      const cleaned = sanitize(text);
      if (cleaned.text !== text) {
        writeFileSync(path, cleaned.text, 'utf8');
        if (!opts.json && !opts.sarif) {
          process.stdout.write('  ' + paint('32', 'fixed') + dim(
            '  removed ' + cleaned.removed + ' character' + (cleaned.removed === 1 ? '' : 's'),
          ) + '\n');
        }
      }
    }
  }
}

if (opts.sarif) {
  const sarif = buildSarif(
    reports.map(({ path, result }) => ({
      path: opts.paths.length ? relative(process.cwd(), path) || path : path,
      result,
    })),
    { version: VERSION },
  );
  const json = JSON.stringify(sarif, null, 2) + '\n';
  if (opts.sarifPath) {
    writeFileSync(opts.sarifPath, json, 'utf8');
    process.stderr.write(
      'secondsight: wrote ' + sarif.runs[0].results.length
      + ' result(s) to ' + opts.sarifPath + '\n',
    );
  } else {
    process.stdout.write(json);
  }
} else if (opts.json) {
  process.stdout.write(JSON.stringify({
    version: 1,
    worst: worst < 0 ? 'CLEAN' : SEVERITY[worst],
    files: reports.map(({ path, result }) => ({
      path,
      verdict: result.verdict.severity < 0 ? 'CLEAN' : result.verdict.label,
      stats: result.stats,
      findings: result.findings.map((f) => ({
        id: f.id,
        title: f.title,
        severity: SEVERITY[f.severity],
        count: f.count,
        positions: f.positions.slice(0, 200),
        decoded: f.decoded,
        intents: f.intents.map((i) => i.label),
        reference: f.reference,
      })),
    })),
  }, null, 2) + '\n');
} else if (opts.paths.length) {
  const flagged = reports.filter((r) => r.result.verdict.severity >= 0).length;
  process.stdout.write('\n' + dim(
    reports.length + ' file' + (reports.length === 1 ? '' : 's') + ' scanned, '
    + flagged + ' with findings',
  ) + '\n');
}

// With --sarif, GitHub's code scanning decides how to surface and gate the
// findings, so the scan step itself must succeed for the upload to run -- unless
// the caller explicitly asked for a --fail-on gate as well.
const gate = opts.sarif && !opts.failOnExplicit ? Infinity : opts.failOn;
process.exit(worst >= gate ? 1 : 0);
