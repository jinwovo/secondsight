#!/usr/bin/env node
/**
 * secondsight -- command line
 *
 *   npx secondsight README.md
 *   cat suspicious.txt | npx secondsight
 *   npx secondsight . --fail-on high      # for CI
 *   npx secondsight --staged              # for a pre-commit hook
 *   npx secondsight --compare mine.md leaked.md
 *
 * Same engine as the web page, no network, no dependencies.
 */

import { readFileSync, writeFileSync, statSync, lstatSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, relative, resolve, extname, basename } from 'node:path';
import { analyze, verdictFor, SEVERITY } from './src/detect.js';
import { sanitize } from './src/sanitize.js';
import { buildSarif } from './src/sarif.js';
import { compare, markSummary } from './src/compare.js';

const VERSION = '1.5.1';

const USAGE = `
secondsight -- find the text you cannot see

  secondsight [options] [file|directory ...]

  With no path, reads standard input.

Options
  --json             machine-readable output
  --sarif [file]     SARIF 2.1.0 for GitHub code scanning (stdout, or to <file>)
  --fix              rewrite files with hidden characters removed
  --staged           scan only the files staged in git -- for a pre-commit hook
  --compare <a> <b>  two copies of one document: find the invisible difference
  --fail-on <level>  exit 1 at or above this severity
                     (info|low|medium|high|critical; default: high)
  --ignore <ids>     comma-separated finding ids to drop (for corpora of
                     deliberate samples: test fixtures, security write-ups)
  --exclude <path>   skip a file or directory; repeatable
  --all              report every file, not just the ones with findings
  --no-gitignore     also scan untracked files that .gitignore excludes
  --no-color         plain output
  -h, --help         this

  --ignore is a command-line flag on purpose. Nothing written inside the text
  being scanned can silence a finding, because the text being scanned is
  exactly the thing you do not trust.
`;

// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const opts = {
  json: false, sarif: false, sarifPath: null,
  fix: false, all: false, color: true, staged: false, compare: false,
  failOn: 3, failOnExplicit: false, paths: [], gitignore: true,
  ignore: new Set(), exclude: [],
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
  else if (a === '--staged') opts.staged = true;
  else if (a === '--compare') opts.compare = true;
  else if (a === '--ignore') {
    for (const id of String(args[++i] || '').split(',')) {
      if (id.trim()) opts.ignore.add(id.trim());
    }
  } else if (a === '--exclude') {
    const p = String(args[++i] || '').trim();
    if (p) opts.exclude.push(slash(p));
  } else if (a === '--all') opts.all = true;
  else if (a === '--no-gitignore') opts.gitignore = false;
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

/** One path spelling, so a Windows backslash and a POSIX slash compare equal. */
function slash(p) {
  return String(p).replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
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
  '.md', '.markdown', '.mdx', '.mdc', '.txt', '.rst', '.adoc', '.tex',
  '.json', '.jsonc', '.json5', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
  '.properties', '.env', '.xml', '.svg', '.csv', '.tsv', '.ipynb', '.lock',
  '.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx', '.vue', '.svelte',
  '.py', '.rb', '.go', '.rs', '.java', '.kt', '.kts', '.scala', '.swift', '.dart',
  '.c', '.h', '.cc', '.cpp', '.hpp', '.cs', '.fs', '.php', '.pl', '.lua', '.r',
  '.ex', '.exs', '.erl', '.hs', '.clj', '.el', '.vim', '.zig', '.nix',
  '.sh', '.bash', '.zsh', '.fish', '.ps1', '.psm1', '.bat', '.cmd',
  '.html', '.htm', '.css', '.scss', '.less', '.sql', '.graphql', '.gql', '.proto',
  '.tf', '.hcl', '.gradle', '.cmake', '.mk',
]);
// Read by name: build files with no extension, and the instruction files an
// agent loads on startup -- the one place a hidden sentence is sure of a reader.
const ALWAYS_READ = new Set([
  'CLAUDE.md', 'AGENTS.md', 'GEMINI.md', 'SKILL.md', 'README.md',
  'Dockerfile', 'Containerfile', 'Makefile', 'Jenkinsfile', 'Procfile', 'Vagrantfile',
  'Gemfile', 'Rakefile', 'Brewfile', 'CODEOWNERS', 'LICENSE',
  '.cursorrules', '.windsurfrules', '.clinerules', '.roorules', '.goosehints',
  '.gitattributes', '.gitignore', '.gitmodules', '.npmrc', '.yarnrc', '.editorconfig',
  '.env', '.envrc',
]);
// Oversized files are reported, never skipped in silence: padding a file past
// a scanner's size limit is the cheapest way around the scanner.
const MAX_BYTES = 8 * 1024 * 1024;
const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'vendor', 'target',
  '.next', '.venv', '__pycache__', 'coverage',
]);

function isReadable(path) {
  const name = basename(path);
  // extname('.env') is '' and extname('.env.production') is '.production', so
  // the whole family of environment files has to be named outright.
  return ALWAYS_READ.has(name) || /^\.env(?:\.|$)/i.test(name)
    || TEXT_EXTENSIONS.has(extname(name).toLowerCase());
}

/** Files that were not scanned, and why. Leaving them out of the report would be lying by omission. */
const skipped = [];

function skip(path, reason) {
  skipped.push({ path, reason });
}

/**
 * A file's text, whatever it was saved as.
 *
 * A UTF-16 file read as UTF-8 comes out as a NUL between every letter: still
 * flagged, but its payload is never decoded, and the decode is the half that
 * matters. A byte-order mark says which it is; without one, NUL bytes in the
 * first 8 KB mean binary. Returns null for binary.
 */
function readText(path) {
  const bytes = readFileSync(path);
  if (bytes[0] === 0xff && bytes[1] === 0xfe) {
    return { text: bytes.subarray(2).toString('utf16le'), encoding: 'utf16le' };
  }
  if (bytes[0] === 0xfe && bytes[1] === 0xff) {
    const body = Buffer.from(bytes.subarray(2, 2 + ((bytes.length - 2) & ~1)));
    return { text: body.swap16().toString('utf16le'), encoding: 'utf16be' };
  }
  if (bytes.subarray(0, 8192).includes(0)) return null;
  return { text: bytes.toString('utf8'), encoding: 'utf8' };
}

/** The inverse of readText, so --fix leaves a file in the encoding it found it in. */
function encodeAs(text, encoding) {
  if (encoding === 'utf8') return Buffer.from(text, 'utf8');
  const body = Buffer.from(text, 'utf16le');
  if (encoding === 'utf16be') body.swap16();
  const bom = Buffer.from(encoding === 'utf16be' ? [0xfe, 0xff] : [0xff, 0xfe]);
  return Buffer.concat([bom, body]);
}

function isExcluded(path) {
  const here = slash(relative(process.cwd(), path) || path);
  const there = slash(path);
  return opts.exclude.some((p) => here === p || there === p
    || here.startsWith(p + '/') || there.startsWith(p + '/'));
}

/**
 * Drop the findings the caller asked to ignore, and restate the verdict from
 * what is left. A filtered report has to be honest about its own severity --
 * silently keeping the old CRITICAL banner over an empty list would be worse
 * than not filtering at all.
 */
function withIgnores(result) {
  if (!opts.ignore.size) return result;
  const findings = result.findings.filter((f) => !opts.ignore.has(f.id));
  if (findings.length === result.findings.length) return result;
  const worstLeft = findings.length ? Math.max(...findings.map((f) => f.severity)) : -1;
  return { ...result, findings, verdict: verdictFor(worstLeft) };
}

// ---------------------------------------------------------------------------
// .gitignore
// ---------------------------------------------------------------------------

/**
 * Files an agent loads by name whether or not git tracks them. CLAUDE.local.md
 * exists to be gitignored, and a rules file nobody committed is still the
 * first thing an agent in that checkout reads -- so ignoring it would skip the
 * one file most certain to have a machine reader.
 */
const AGENT_FILES = new Set([
  'CLAUDE.md', 'CLAUDE.local.md', 'AGENTS.md', 'AGENTS.override.md', 'GEMINI.md', 'SKILL.md',
  'copilot-instructions.md', '.cursorrules', '.windsurfrules', '.clinerules', '.roorules', '.goosehints',
]);

function isAgentFile(path) {
  const name = basename(path);
  return AGENT_FILES.has(name) || extname(name).toLowerCase() === '.mdc';
}

/** Paths git would not commit, as absolute slash-paths; directories end in '/'. */
const gitIgnored = new Set();
/** How many ignored paths the walk actually stepped over, for the report. */
let ignoredCount = 0;

/**
 * Ask git which untracked paths under a directory its ignore rules exclude.
 *
 * Only untracked paths can be ignored: a tracked file is scanned whatever
 * .gitignore says, so an ignore rule can hide a build directory from the scan
 * but never a file that is in the history. Outside a repository, or without
 * git, nothing is ignored and the walk is exactly what it was.
 */
function loadGitIgnored(dir) {
  let out;
  try {
    out = execFileSync('git', ['ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--directory'], {
      cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    return;
  }
  for (const entry of out.split('\0')) {
    if (!entry) continue;
    const abs = slash(resolve(dir, entry));
    gitIgnored.add(entry.endsWith('/') ? abs + '/' : abs);
  }
}

function isGitIgnored(path, isDir) {
  if (!gitIgnored.size) return false;
  const abs = slash(resolve(path));
  return gitIgnored.has(abs) || (isDir && gitIgnored.has(abs + '/'));
}

function collect(path, out = [], named = true) {
  let st;
  try { st = named ? statSync(path) : lstatSync(path); } catch { fail('cannot read ' + path); }
  if (isExcluded(path)) return out;
  if (named && st.isDirectory() && opts.gitignore) loadGitIgnored(path);
  if (!named && isGitIgnored(path, st.isDirectory()) && !(st.isFile() && isAgentFile(path))) {
    ignoredCount++;
    return out;
  }
  // A path named on the command line is followed wherever it points. A link
  // met while walking is not: it can lead out of the tree, or round in a loop.
  if (st.isSymbolicLink()) return out;
  if (st.isDirectory()) {
    if (!named && SKIP_DIRS.has(basename(path))) return out;
    for (const entry of readdirSync(path)) collect(join(path, entry), out, false);
    return out;
  }
  // A file someone named is read whatever its extension; they asked for it.
  if (!named && !isReadable(path)) return out;
  if (st.size > MAX_BYTES) {
    skip(path, 'larger than ' + (MAX_BYTES >> 20) + ' MB');
    return out;
  }
  out.push(path);
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
// --compare: two copies of one document
// ---------------------------------------------------------------------------

function wrapText(text, width, indent) {
  const lines = [];
  let line = '';
  for (const word of text.split(/\s+/)) {
    if (line && (line + ' ' + word).length > width) { lines.push(line); line = word; }
    else line = line ? line + ' ' + word : word;
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join('\n');
}

function runCompare(pathA, pathB) {
  let a;
  let b;
  try { a = readFileSync(pathA, 'utf8'); } catch { fail('cannot read ' + pathA); }
  try { b = readFileSync(pathB, 'utf8'); } catch { fail('cannot read ' + pathB); }

  const cmp = compare(a, b);

  if (opts.json) {
    process.stdout.write(JSON.stringify({
      version: 1,
      relation: cmp.relation,
      headline: cmp.headline,
      detail: cmp.detail,
      sameVisible: cmp.sameVisible,
      sameBytes: cmp.sameBytes,
      differingCodepoints: cmp.differingCodepoints,
      copies: cmp.copies.map((copy, i) => ({
        path: i === 0 ? pathA : pathB,
        hidden: copy.hidden,
        signature: copy.signature,
        payloads: copy.payloads.map((p) => ({ id: p.id, decoded: p.decoded })),
      })),
      differences: cmp.differences.slice(0, 200).map((d) => ({
        at: d.at,
        context: d.context,
        a: d.a ? d.a.abbrs : [],
        b: d.b ? d.b.abbrs : [],
      })),
    }, null, 2) + '\n');
    return cmp;
  }

  const TONE = { empty: '2', identical: '32', marked: '1;31', edited: '33' };
  process.stdout.write('\n' + bold(pathA) + dim('  vs  ') + bold(pathB) + '\n');
  process.stdout.write(paint(TONE[cmp.relation], cmp.headline) + '\n');
  process.stdout.write(dim(wrapText(cmp.detail, 76, '  ')) + '\n');

  for (const copy of cmp.copies) {
    const where = copy.label === 'A' ? pathA : pathB;
    process.stdout.write(
      '\n  ' + bold('copy ' + copy.label) + dim('  ' + where) + '\n'
      + dim('    ' + copy.hidden + ' hidden character' + (copy.hidden === 1 ? '' : 's'))
      + (copy.signature ? dim('    fingerprint ') + paint('36', copy.signature) : '') + '\n',
    );
    for (const payload of copy.payloads) {
      process.stdout.write(
        '    ' + paint('36', 'says: ')
        + JSON.stringify(payload.decoded.replace(/\s+/g, ' ').slice(0, 160)) + '\n',
      );
    }
  }

  if (cmp.differences.length) {
    process.stdout.write('\n  ' + bold('where they differ') + '\n');
    for (const d of cmp.differences.slice(0, 8)) {
      const context = d.context ? d.context.replace(/\s+/g, ' ').slice(-24) : '';
      process.stdout.write(
        dim('    after ' + d.at + ' visible characters')
        + (context ? dim('  ...' + context) : '') + '\n'
        + '      A  ' + markSummary(d.a, 10, d.divergeAt) + '\n'
        + '      B  ' + markSummary(d.b, 10, d.divergeAt) + '\n',
      );
    }
    if (cmp.differences.length > 8) {
      process.stdout.write(dim('    ... and ' + (cmp.differences.length - 8) + ' more') + '\n');
    }
  }
  process.stdout.write('\n');
  return cmp;
}

// ---------------------------------------------------------------------------
// --staged: the files git is about to commit
// ---------------------------------------------------------------------------

function stagedFiles() {
  let out = '';
  try {
    out = execFileSync('git', ['diff', '--cached', '--name-only', '--diff-filter=ACM'], {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    fail('--staged needs to run inside a git repository');
  }
  return out.split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((path) => existsAsPath(path) && isReadable(path) && !isExcluded(path))
    .filter((path) => {
      if (statSync(path).size <= MAX_BYTES) return true;
      skip(path, 'larger than ' + (MAX_BYTES >> 20) + ' MB');
      return false;
    });
}

// ---------------------------------------------------------------------------

if (opts.compare) {
  if (opts.paths.length !== 2) fail('--compare takes exactly two files');
  const cmp = runCompare(opts.paths[0], opts.paths[1]);
  // A watermark difference is a fact about the pair, not about either file on
  // its own, so it gets its own exit code: 1 when the two copies are separable.
  process.exit(cmp.relation === 'marked' ? 1 : 0);
}

const reading = opts.staged || opts.paths.length > 0;
const targets = opts.staged ? stagedFiles() : opts.paths.flatMap((p) => collect(p));
const reports = [];
let worst = -1;

if (!reading) {
  const text = readStdin();
  const result = withIgnores(analyze(text));
  worst = result.verdict.severity;
  reports.push({ path: '<stdin>', result });
  if (!opts.json && !opts.sarif) reportText('<stdin>', result);
} else {
  for (const path of targets) {
    let read;
    try { read = readText(path); } catch { skip(path, 'unreadable'); continue; }
    if (!read) { skip(path, 'binary'); continue; }
    const { text, encoding } = read;
    const result = withIgnores(analyze(text));
    worst = Math.max(worst, result.verdict.severity);
    reports.push({ path, result });
    if (!opts.json && !opts.sarif) reportText(relative(process.cwd(), path) || path, result);

    if (opts.fix && result.verdict.severity >= 0) {
      const cleaned = sanitize(text);
      if (cleaned.text !== text) {
        writeFileSync(path, encodeAs(cleaned.text, encoding));
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
      path: reading ? relative(process.cwd(), path) || path : path,
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
    skipped,
    gitignored: ignoredCount,
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
} else if (reading) {
  const flagged = reports.filter((r) => r.result.verdict.severity >= 0).length;
  process.stdout.write('\n' + dim(
    reports.length + ' file' + (reports.length === 1 ? '' : 's') + ' scanned, '
    + flagged + ' with findings',
  ) + '\n');
}

if (ignoredCount && !opts.json && !opts.sarif) {
  process.stderr.write(
    'secondsight: ' + ignoredCount + ' path' + (ignoredCount === 1 ? '' : 's')
    + ' ignored by git were not scanned (--no-gitignore to include them)\n',
  );
}

// On stderr in every mode, so it survives --json and --sarif on stdout. Only
// files a scan would have read land here; a directory of images is not news.
for (const { path, reason } of skipped) {
  process.stderr.write(
    'secondsight: not scanned (' + reason + '): ' + (relative(process.cwd(), path) || path) + '\n',
  );
}

// With --sarif, GitHub's code scanning decides how to surface and gate the
// findings, so the scan step itself must succeed for the upload to run -- unless
// the caller explicitly asked for a --fail-on gate as well.
const gate = opts.sarif && !opts.failOnExplicit ? Infinity : opts.failOn;
process.exit(worst >= gate ? 1 : 0);
