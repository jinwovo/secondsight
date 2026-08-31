/* secondsight -- interface
 *
 * Everything runs here, in this tab. The page makes no network request after
 * it loads, which is the point: the text you would most want to check is the
 * text you would least want to upload.
 */

import { analyze, visibleText, humanText, SEVERITY } from '../src/detect.js';
import { sanitize } from '../src/sanitize.js';
import { SPECIMENS, specimenById } from '../src/specimens.js';
import { SCHEMES, encodeZeroWidth } from '../src/encode.js';
import { compare } from '../src/compare.js';
import { hex } from '../src/catalog.js';

const $ = (id) => document.getElementById(id);

const el = {
  input: $('input'), inputBlock: document.querySelector('.input-block'),
  dropzone: $('dropzone'),
  specimens: $('specimens'),
  spectrum: $('spectrum'), spectrumReadout: $('spectrum-readout'), spectrumHint: $('spectrum-hint'),
  human: $('view-human'), machine: $('view-machine'),
  countHuman: $('count-human'), countMachine: $('count-machine'),
  verdict: $('verdict'), verdictLabel: $('verdict-label'), verdictLine: $('verdict-line'),
  findings: $('findings'),
  actions: $('actions'), cleanSummary: $('clean-summary'),
  toast: $('toast'), explain: $('explain'),
  lab: $('lab'), labInput: $('lab-input'), labCover: $('lab-cover'),
  labScheme: $('lab-scheme'), labOutput: $('lab-output'),
  labHint: $('lab-hint'), labStats: $('lab-stats'),
  cmpA: $('cmp-a'), cmpB: $('cmp-b'), cmpOut: $('cmp-out'),
};

// The machine pane renders one node per codepoint. Past a few thousand that
// stops being informative and starts being a scroll bar, so it is capped and
// the cap is stated rather than hidden.
const RENDER_CAP = 3000;

// A 208-character payload drawn one chip per codepoint is the whole point --
// seeing the wall is what makes the scale land. Past a few dozen it stops
// adding anything and becomes a scroll bar, so a long run shows its first
// RUN_HEAD chips and folds the rest into one chip that opens on click.
const RUN_COLLAPSE = 64;
const RUN_HEAD = 48;

// The abbreviations inside a run vary per character (TAG a, TAG b, TAG SP),
// so listing them says nothing. Name the kind instead, unless the run really
// is made of one or two characters -- which is exactly the case where the
// pair of them is the interesting fact.
const KIND_LABEL = {
  'tags': 'TAGS',
  'variation-selector': 'VS',
  'zero-width': 'ZERO-WIDTH',
  'private-use': 'PUA',
  'noncharacter': 'NONCHAR',
};

let current = analyze('');
let spectrumCells = [];

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function toast(message) {
  el.toast.textContent = message;
  el.toast.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.toast.classList.remove('show'), 1900);
}

async function copy(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); toast(message); }
    catch { toast('could not copy -- select it manually'); }
    ta.remove();
  }
}

const num = (n) => n.toLocaleString('en-US');

// The sticky bar covers the top of the viewport, so "scrolled to" and "visible"
// are not the same thing. CSS scroll-margin handles where a jump lands; this
// decides whether to jump at all, because scrolling a page that was already
// showing the right thing is how a click ends up feeling like it went wrong.
const NAV_CLEARANCE = 78;

function ensureVisible(node, { force = false } = {}) {
  const box = node.getBoundingClientRect();
  const roomBelow = window.innerHeight - NAV_CLEARANCE;
  const fullyInView = box.top >= NAV_CLEARANCE && box.bottom <= window.innerHeight;
  const topInView = box.top >= NAV_CLEARANCE && box.top < window.innerHeight - 80;
  if (!force && (fullyInView || topInView)) return;
  node.scrollIntoView({
    block: box.height > roomBelow ? 'start' : 'nearest',
    behavior: 'smooth',
  });
}

// ---------------------------------------------------------------------------
// The two panes
// ---------------------------------------------------------------------------

function renderHuman(result) {
  // What a person has in front of them: the invisible characters removed, the
  // directional ones kept so the browser still reorders the line the way their
  // editor would. See humanText() for why the rest must not be painted.
  el.human.textContent = humanText(result);
  el.countHuman.textContent = result.text
    ? num([...visibleText(result)].length) + ' characters'
    : '';
}

function chipFor(cell) {
  const chip = document.createElement('span');
  chip.className = 'chip k-' + cell.info.kind + (cell.benign ? ' benign' : '');
  chip.textContent = cell.info.abbr;
  chip.dataset.offset = String(cell.offset);
  chip.title = cell.info.name + '  (' + hex(cell.cp) + ')'
    + (cell.benign ? '\n\nExpected here: ' + cell.benignReason : '')
    + (cell.info.note ? '\n\n' + cell.info.note : '');
  return chip;
}

/** One chip standing in for the tail of a long run of hidden characters. */
function runChipFor(run) {
  const kind = run[0].info.kind;
  const abbrs = [...new Set(run.map((c) => c.info.abbr))];
  const chip = document.createElement('button');
  chip.type = 'button';
  chip.className = 'chip chip--run k-' + kind + (run[0].benign ? ' benign' : '');
  chip.textContent = (abbrs.length <= 2 ? abbrs.join('/') : KIND_LABEL[kind] || kind.toUpperCase())
    + ' x' + num(run.length) + ' more';
  chip.title = num(run.length) + ' more ' + kind + ' characters, folded so this pane stays'
    + ' readable.\n\nWhat they spell is in the findings below. Click to open the run.';
  chip.addEventListener('click', () => {
    const opened = document.createDocumentFragment();
    for (const cell of run) opened.appendChild(chipFor(cell));
    chip.replaceWith(opened);
  });
  return chip;
}

/** How far a run of the same kind of hidden character extends from `start`. */
function runEnd(cells, start, limit) {
  const first = cells[start];
  let end = start;
  while (
    end < limit
    && cells[end].info
    && cells[end].info.kind === first.info.kind
    && cells[end].benign === first.benign
  ) end++;
  return end;
}

function renderMachine(result) {
  const frag = document.createDocumentFragment();
  const cells = result.cells;
  const limit = Math.min(cells.length, RENDER_CAP);
  let buffer = '';

  const flush = () => {
    if (buffer) { frag.appendChild(document.createTextNode(buffer)); buffer = ''; }
  };

  for (let i = 0; i < limit; i++) {
    const cell = cells[i];
    if (cell.info) {
      flush();
      // A newline is structure, not a payload, so runs of them are never folded.
      if (cell.info.kind !== 'linebreak') {
        const end = runEnd(cells, i, limit);
        if (end - i >= RUN_COLLAPSE) {
          for (let k = i; k < i + RUN_HEAD; k++) frag.appendChild(chipFor(cells[k]));
          frag.appendChild(runChipFor(cells.slice(i + RUN_HEAD, end)));
          i = end - 1;
          continue;
        }
      }
      frag.appendChild(chipFor(cell));
      if (cell.info.kind === 'linebreak') frag.appendChild(document.createTextNode('\n'));
    } else if (cell.confusable) {
      flush();
      const span = document.createElement('span');
      span.className = 'glyph-confusable';
      span.textContent = cell.ch;
      span.dataset.offset = String(cell.offset);
      span.title = hex(cell.cp) + ' -- ' + cell.confusable.script
        + '\n\nDrawn like "' + cell.confusable.to + '". It is not "' + cell.confusable.to + '".';
      frag.appendChild(span);
    } else {
      buffer += cell.ch;
    }
  }
  flush();

  if (cells.length > limit) {
    const note = document.createElement('span');
    note.className = 'truncated';
    note.textContent = num(cells.length - limit) + ' more codepoints not drawn. '
      + 'Every one of them was still analysed -- the findings below cover the whole input.';
    frag.appendChild(note);
  }

  el.machine.replaceChildren(frag);

  const s = result.stats;
  el.countMachine.textContent = result.text
    ? num(s.codepoints) + ' codepoints'
      + (s.hidden ? '  |  ' + num(s.hidden) + ' invisible' : '')
    : '';
}

// ---------------------------------------------------------------------------
// Spectrum
// ---------------------------------------------------------------------------

const KIND_TONE = {
  'tags': ['--sev-4', 5],
  'variation-selector': ['--sev-4', 5],
  'zero-width': ['--sev-3', 4.5],
  'bidi': ['bidi', 4.5],
  'control': ['--sev-4', 4],
  'ansi': ['--sev-4', 4],
  'noncharacter': ['--sev-4', 4],
  'marker': ['--sev-2', 3.5],
  'deprecated': ['--sev-2', 3.5],
  'private-use': ['--sev-2', 3.5],
  'space': ['--sev-1', 1.4],
  'linebreak': ['--sev-1', 1.4],
};

function paletteFrom(styles) {
  const read = (name) => styles.getPropertyValue(name).trim();
  return {
    '--sev-1': read('--sev-1'),
    '--sev-2': read('--sev-2'),
    '--sev-3': read('--sev-3'),
    '--sev-4': read('--sev-4'),
    'bidi': '#c678dd',
    'benign': read('--sev--1'),
    'plain': read('--fg-faint'),
    'panel': read('--panel'),
  };
}

/** Priority, colour and bar height for one codepoint. */
function tone(cell) {
  if (cell.info) {
    const [key, priority] = KIND_TONE[cell.info.kind] || ['--sev-2', 3];
    if (cell.benign) return { priority: 1.6, key: 'benign', height: 0.45 };
    return { priority, key, height: priority >= 4 ? 1 : 0.7 };
  }
  if (cell.confusable) return { priority: 2.5, key: '--sev-2', height: 0.62 };
  if (/\s/.test(cell.ch)) return { priority: 0.4, key: 'plain', height: 0.14 };
  return { priority: 1, key: 'plain', height: 0.3 };
}

function renderSpectrum(result) {
  const canvas = el.spectrum;
  const dpr = window.devicePixelRatio || 1;
  const cssWidth = canvas.clientWidth || 800;
  const cssHeight = 56;
  canvas.width = Math.round(cssWidth * dpr);
  canvas.height = Math.round(cssHeight * dpr);

  const ctx = canvas.getContext('2d');
  const palette = paletteFrom(getComputedStyle(document.documentElement));
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  const cells = result.cells;
  if (!cells.length) {
    spectrumCells = [];
    el.spectrumHint.textContent = 'every codepoint, in order';
    return;
  }

  // One column per pixel. When several codepoints share a column the loudest
  // one wins, so a payload can never be averaged into invisibility.
  const columns = Math.max(1, Math.floor(cssWidth));
  const perColumn = cells.length / columns;
  const picked = new Array(columns).fill(null);

  for (let i = 0; i < cells.length; i++) {
    const x = Math.min(columns - 1, Math.floor(i / perColumn));
    const t = tone(cells[i]);
    const held = picked[x];
    if (!held || t.priority > held.tone.priority) picked[x] = { tone: t, index: i };
  }

  spectrumCells = picked;

  const colWidth = Math.max(1, cssWidth / columns);
  for (let x = 0; x < columns; x++) {
    const slot = picked[x];
    if (!slot) continue;
    const { tone: t } = slot;
    const colour = palette[t.key] || palette.plain;
    const h = Math.max(2, cssHeight * t.height);
    const y = (cssHeight - h) / 2;

    if (t.priority >= 4) {
      ctx.shadowColor = colour;
      ctx.shadowBlur = 7;
    } else {
      ctx.shadowBlur = 0;
    }
    ctx.globalAlpha = t.priority >= 4 ? 1 : t.priority >= 2 ? 0.85 : 0.34;
    ctx.fillStyle = colour;
    ctx.fillRect(x * colWidth, y, Math.max(1, colWidth - 0.15), h);
  }
  ctx.shadowBlur = 0;
  ctx.globalAlpha = 1;

  const hidden = result.stats.hidden;
  el.spectrumHint.textContent = hidden
    ? num(cells.length) + ' codepoints -- the bright ones are not on your screen'
    : num(cells.length) + ' codepoints, nothing hidden';
}

function spectrumHover(event) {
  if (!spectrumCells.length) { el.spectrumReadout.textContent = ''; return; }
  const rect = el.spectrum.getBoundingClientRect();
  const x = Math.floor(event.clientX - rect.left);
  const slot = spectrumCells[Math.max(0, Math.min(spectrumCells.length - 1, x))];
  if (!slot) { el.spectrumReadout.textContent = ''; return; }

  const cell = current.cells[slot.index];
  const label = cell.info
    ? cell.info.name + (cell.benign ? '  -- expected here' : '')
    : cell.confusable
      ? 'looks like "' + cell.confusable.to + '", is ' + cell.confusable.script
      : JSON.stringify(cell.ch);

  el.spectrumReadout.innerHTML = '';
  const strong = document.createElement('b');
  strong.textContent = hex(cell.cp);
  el.spectrumReadout.append(strong, '  ' + label + '   at offset ' + cell.offset);
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function renderFindings(result) {
  el.findings.replaceChildren();

  const sev = result.verdict.severity;
  el.verdict.dataset.severity = sev < 0 ? 'none' : String(sev);
  el.verdictLabel.textContent = result.text ? result.verdict.label : 'CLEAN';
  el.verdictLine.textContent = result.text
    ? result.verdict.line
    : 'Paste something above.';

  for (const f of result.findings) {
    const card = document.createElement('article');
    card.className = 'finding';

    const head = document.createElement('div');
    head.className = 'finding-head';

    const badge = document.createElement('span');
    badge.className = 'badge s' + f.severity;
    badge.textContent = SEVERITY[f.severity];

    const title = document.createElement('span');
    title.className = 'finding-title';
    title.textContent = f.title;

    head.append(badge, title);

    if (f.count > 1) {
      const count = document.createElement('span');
      count.className = 'finding-count';
      // A markup finding counts passages, not codepoints. Calling two hidden
      // paragraphs "2 characters" would be a small lie in a tool whose only
      // claim is that it tells you exactly what is there.
      count.textContent = num(f.count) + (f.kind === 'markup' ? ' places' : ' characters');
      head.appendChild(count);
    }
    card.appendChild(head);

    if (f.decoded) {
      const box = document.createElement('div');
      box.className = 'decoded';

      const label = document.createElement('div');
      label.className = 'decoded-label';
      label.textContent = 'what it actually says';
      if (f.scheme) {
        const scheme = document.createElement('span');
        scheme.className = 'scheme';
        scheme.textContent = f.scheme;
        label.appendChild(scheme);
      }

      const pre = document.createElement('pre');
      pre.textContent = f.decoded;

      box.append(label, pre);
      card.appendChild(box);
    }

    if (f.intents.length) {
      const row = document.createElement('div');
      row.className = 'intents';
      for (const i of f.intents) {
        const tag = document.createElement('span');
        tag.className = 'intent';
        tag.textContent = i.label;
        row.appendChild(tag);
      }
      card.appendChild(row);
    }

    const detail = document.createElement('p');
    detail.className = 'finding-detail';
    detail.textContent = f.detail;
    card.appendChild(detail);

    if (f.samples.length) {
      const row = document.createElement('div');
      row.className = 'samples';
      for (const s of f.samples) {
        const tag = document.createElement('span');
        tag.className = 'sample';
        tag.textContent = s;
        row.appendChild(tag);
      }
      card.appendChild(row);
    }

    if (f.reference) {
      const ref = document.createElement('div');
      ref.className = 'reference';
      ref.textContent = f.reference;
      card.appendChild(ref);
    }

    // Clicking a finding should show you the thing it found. For a single
    // hidden character that means its chip; for a passage that is hidden by
    // how it is marked up, no chip exists, so the passage is selected in the
    // input instead -- which is where it actually is.
    if (f.positions.length || f.spans.length) {
      card.style.cursor = 'pointer';
      card.title = f.spans.length ? 'Select it in the input' : 'Jump to the first one';
      card.addEventListener('click', () => {
        const chip = f.positions.length
          ? el.machine.querySelector('[data-offset="' + f.positions[0] + '"]')
          : null;
        if (chip) {
          chip.scrollIntoView({ block: 'center', behavior: 'smooth' });
          chip.animate(
            [{ outline: '2px solid var(--accent)' }, { outline: '2px solid transparent' }],
            { duration: 1300 },
          );
          return;
        }
        const [start, end] = f.spans[0] || [];
        if (start === undefined) return;
        el.input.focus({ preventScroll: true });
        el.input.setSelectionRange(start, end);
        ensureVisible(el.inputBlock, { force: true });
      });
    }

    el.findings.appendChild(card);
  }

  el.actions.hidden = sev < 0;
}

// ---------------------------------------------------------------------------
// Cleaning
// ---------------------------------------------------------------------------

function currentOptions() {
  return {
    stripHidden: $('opt-hidden').checked,
    stripAnsi: $('opt-ansi').checked,
    normalizeSpaces: $('opt-spaces').checked,
    foldConfusables: $('opt-fold').checked,
  };
}

function cleaned() {
  return sanitize(current.text, currentOptions());
}

function updateCleanSummary() {
  if (el.actions.hidden) return;
  const result = cleaned();
  if (result.changes.length) {
    el.cleanSummary.textContent =
      result.changes.map((c) => c.label + (c.count > 1 ? ' x' + c.count : '')).slice(0, 3).join(', ')
      + (result.changes.length > 3 ? ', +' + (result.changes.length - 3) + ' more' : '');
    return;
  }
  // Some findings are not made of characters at all. Offering to strip
  // characters that are not there would be a button that lies.
  const markupOnly = current.findings.length
    && current.findings.every((f) => f.kind === 'markup');
  el.cleanSummary.textContent = markupOnly
    ? 'these findings are in the markup, not the characters -- removing characters cannot fix them'
    : 'nothing to change with these options';
}

function buildReport() {
  const r = current;
  const lines = [
    '# secondsight report',
    '',
    'Generated in the browser. No text was transmitted.',
    '',
    '- verdict: ' + (r.verdict.severity < 0 ? 'CLEAN' : r.verdict.label),
    '- codepoints: ' + r.stats.codepoints,
    '- visible: ' + r.stats.visible,
    '- hidden: ' + r.stats.hidden,
    '- expected-hidden: ' + r.stats.benignHidden,
    '',
  ];
  if (!r.findings.length) lines.push('No findings.');
  for (const f of r.findings) {
    lines.push('## [' + SEVERITY[f.severity] + '] ' + f.title, '');
    lines.push('- occurrences: ' + f.count);
    if (f.reference) lines.push('- reference: ' + f.reference);
    if (f.scheme) lines.push('- encoding: ' + f.scheme);
    if (f.positions.length) {
      lines.push('- offsets: ' + f.positions.slice(0, 40).join(', ')
        + (f.positions.length > 40 ? ', ...' : ''));
    }
    lines.push('', f.detail, '');
    if (f.decoded) lines.push('Decoded payload:', '', '```', f.decoded, '```', '');
    if (f.intents.length) {
      lines.push('Reads as: ' + f.intents.map((i) => i.label).join(', '), '');
    }
  }
  return lines.join('\n');
}

function download(filename, text) {
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------------------------------------------------------------------------
// Main update
// ---------------------------------------------------------------------------

function update() {
  current = analyze(el.input.value);
  renderHuman(current);
  renderMachine(current);
  renderSpectrum(current);
  renderFindings(current);
  updateCleanSummary();
}

let pending = null;
function scheduleUpdate() {
  clearTimeout(pending);
  pending = setTimeout(update, 110);
}

function setInput(text, { markSpecimen = null } = {}) {
  el.input.value = text;
  for (const button of el.specimens.children) {
    button.setAttribute('aria-pressed', String(button.dataset.id === markSpecimen));
  }
  update();
}

// ---------------------------------------------------------------------------
// Gallery
// ---------------------------------------------------------------------------

// The gallery sits between the input and the analysis, so it has to earn its
// height. Two rows are enough to show the range and the control; the rest are
// one click away rather than a screen of scrolling for everyone.
const SPECIMENS_SHOWN = 7;

function renderGallery() {
  const upFront = new Set([...SPECIMENS.slice(0, SPECIMENS_SHOWN).map((s) => s.id), 'clean']);
  const frag = document.createDocumentFragment();
  for (const s of SPECIMENS) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'specimen'
      + (s.id === 'clean' ? ' control' : '')
      + (upFront.has(s.id) ? '' : ' specimen--extra');
    button.dataset.id = s.id;
    button.setAttribute('aria-pressed', 'false');

    const title = document.createElement('span');
    title.className = 'st';
    title.textContent = s.title;

    const blurb = document.createElement('span');
    blurb.className = 'sb';
    blurb.textContent = s.blurb;

    button.append(title, blurb);
    button.addEventListener('click', () => {
      setInput(s.build(), { markSpecimen: s.id });
      history.replaceState(null, '', '#' + s.id);
      showWhy(s);
      // The input sits directly above this row, so it is usually already on
      // screen. Only scroll when it genuinely is not.
      ensureVisible(el.inputBlock);
    });
    frag.appendChild(button);
  }
  el.specimens.replaceChildren(frag);

  const hidden = SPECIMENS.length - [...el.specimens.children]
    .filter((b) => !b.classList.contains('specimen--extra')).length;
  if (!hidden) return;

  const more = $('specimens-more');
  more.hidden = false;
  more.textContent = 'Show ' + hidden + ' more';
  more.addEventListener('click', () => {
    const open = el.specimens.classList.toggle('all');
    more.textContent = open ? 'Show fewer' : 'Show ' + hidden + ' more';
    more.setAttribute('aria-expanded', String(open));
  });
}

function showWhy(specimen) {
  const card = document.createElement('article');
  card.className = 'finding';

  const head = document.createElement('div');
  head.className = 'finding-head';
  const badge = document.createElement('span');
  badge.className = 'badge s0';
  badge.textContent = 'WHY IT WORKS';
  const title = document.createElement('span');
  title.className = 'finding-title';
  title.textContent = specimen.title;
  head.append(badge, title);

  const detail = document.createElement('p');
  detail.className = 'finding-detail';
  detail.textContent = specimen.why;

  card.append(head, detail);

  if (specimen.reference) {
    const ref = document.createElement('div');
    ref.className = 'reference';
    ref.textContent = specimen.reference;
    card.appendChild(ref);
  }
  el.findings.appendChild(card);
}

// ---------------------------------------------------------------------------
// Lab
// ---------------------------------------------------------------------------

function renderLab() {
  for (const scheme of SCHEMES) {
    const option = document.createElement('option');
    option.value = scheme.id;
    option.textContent = scheme.name;
    el.labScheme.appendChild(option);
  }
  updateLab();
}

function updateLab() {
  const scheme = SCHEMES.find((s) => s.id === el.labScheme.value) || SCHEMES[0];
  el.labHint.textContent = scheme.hint;

  const payload = scheme.encode(el.labInput.value);
  const cover = el.labCover.value;
  const combined = scheme.id === 'bidi'
    ? cover + ' ' + payload
    : cover + payload;

  el.labOutput.value = combined;
  const visible = [...cover].length;
  const total = [...combined].length;
  el.labStats.textContent = visible + ' characters on screen, ' + total + ' in the string';
}

// ---------------------------------------------------------------------------
// Compare two copies
// ---------------------------------------------------------------------------

// Twelve marks is about as many as fit on one line at this size, and the
// window opens two before the divergence so the last matching pair is visible
// next to the first mismatched one. A difference you have to take on trust is
// not much better than no difference at all.
const MARK_WINDOW = 12;

const DEMO_MEMO = 'CONFIDENTIAL -- Board summary, Q3\n\n'
  + 'Headcount plan approved as circulated. Do not forward.';

function markRow(label, mark, other, from) {
  const row = document.createElement('div');
  row.className = 'cmp-row';

  const tag = document.createElement('span');
  tag.className = 'cmp-tag';
  tag.textContent = label;
  row.appendChild(tag);

  if (!mark) {
    const none = document.createElement('span');
    none.className = 'cmp-mark absent';
    none.textContent = 'nothing here';
    row.appendChild(none);
    return row;
  }

  const start = Math.max(0, Math.min(from - 2, mark.abbrs.length - MARK_WINDOW));
  const end = Math.min(mark.abbrs.length, start + MARK_WINDOW);

  if (start > 0) {
    const lead = document.createElement('span');
    lead.className = 'cmp-ell';
    lead.textContent = '...';
    row.appendChild(lead);
  }
  for (let i = start; i < end; i++) {
    const badge = document.createElement('span');
    const matches = other && other.cps[i] === mark.cps[i];
    badge.className = 'cmp-mark ' + (matches ? 'same' : 'differs');
    badge.textContent = mark.abbrs[i];
    row.appendChild(badge);
  }
  const tail = document.createElement('span');
  tail.className = 'cmp-ell';
  tail.textContent = (end < mark.abbrs.length ? '... ' : '') + '[' + mark.abbrs.length + ']';
  row.appendChild(tail);
  return row;
}

function copyCard(copy) {
  const card = document.createElement('article');
  card.className = 'cmp-copy';

  const head = document.createElement('div');
  head.className = 'cmp-copy-head';
  const tag = document.createElement('span');
  tag.className = 'cmp-tag';
  tag.textContent = 'COPY ' + copy.label;
  head.appendChild(tag);
  if (copy.signature) {
    const fp = document.createElement('span');
    fp.className = 'cmp-fp';
    fp.textContent = copy.signature;
    fp.title = 'A short id for this copy\'s invisible marks. Same id, same marks.';
    head.appendChild(fp);
  }
  card.appendChild(head);

  const stat = document.createElement('div');
  stat.className = 'cmp-copy-stat';
  stat.textContent = copy.text
    ? num(copy.hidden) + ' hidden character' + (copy.hidden === 1 ? '' : 's')
      + '  |  ' + num([...copy.visible].length) + ' visible'
    : 'empty';
  card.appendChild(stat);

  for (const payload of copy.payloads) {
    const box = document.createElement('div');
    box.className = 'decoded';
    const label = document.createElement('div');
    label.className = 'decoded-label';
    label.textContent = 'what this copy carries';
    const pre = document.createElement('pre');
    pre.textContent = payload.decoded;
    box.append(label, pre);
    card.appendChild(box);
  }

  if (copy.text) {
    const row = document.createElement('div');
    row.className = 'action-row';
    row.style.marginTop = '12px';
    const send = document.createElement('button');
    send.type = 'button';
    send.className = 'ubtn';
    send.textContent = 'Open copy ' + copy.label + ' above';
    send.addEventListener('click', () => {
      setInput(copy.text);
      ensureVisible(el.inputBlock, { force: true });
    });
    row.appendChild(send);
    card.appendChild(row);
  }
  return card;
}

function renderCompare() {
  const a = el.cmpA.value;
  const b = el.cmpB.value;
  if (!a && !b) { el.cmpOut.replaceChildren(); return; }

  const cmp = compare(a, b);
  const frag = document.createDocumentFragment();

  const verdict = document.createElement('div');
  verdict.className = 'cmp-verdict';
  verdict.dataset.relation = cmp.relation;
  const headline = document.createElement('div');
  headline.className = 'cmp-headline';
  headline.textContent = cmp.headline;
  const detail = document.createElement('p');
  detail.className = 'cmp-detail';
  detail.textContent = cmp.detail;
  verdict.append(headline, detail);
  frag.appendChild(verdict);

  const copies = document.createElement('div');
  copies.className = 'cmp-copies';
  for (const copy of cmp.copies) copies.appendChild(copyCard(copy));
  frag.appendChild(copies);

  if (cmp.differences.length) {
    const list = document.createElement('div');
    list.className = 'cmp-diffs';
    for (const d of cmp.differences.slice(0, 6)) {
      const box = document.createElement('div');
      box.className = 'cmp-diff';
      const where = document.createElement('div');
      where.className = 'cmp-diff-where';
      where.textContent = 'after ' + num(d.at) + ' visible characters';
      if (d.context.trim()) {
        const quote = document.createElement('b');
        quote.textContent = '  ...' + d.context.replace(/\s+/g, ' ').slice(-26);
        where.appendChild(quote);
      }
      box.appendChild(where);
      box.appendChild(markRow('A', d.a, d.b, d.divergeAt));
      box.appendChild(markRow('B', d.b, d.a, d.divergeAt));
      list.appendChild(box);
    }
    if (cmp.differences.length > 6) {
      const more = document.createElement('div');
      more.className = 'cmp-diff-where';
      more.textContent = 'and ' + num(cmp.differences.length - 6) + ' more positions.';
      list.appendChild(more);
    }
    frag.appendChild(list);
  }

  el.cmpOut.replaceChildren(frag);
}

let comparePending = null;
function scheduleCompare() {
  clearTimeout(comparePending);
  comparePending = setTimeout(renderCompare, 140);
}

function loadCompareDemo({ quiet = false } = {}) {
  const marked = (who) => DEMO_MEMO.replace('approved as', 'approved as' + encodeZeroWidth(who));
  el.cmpA.value = marked('recipient=j.kown;copy=0447');
  el.cmpB.value = marked('recipient=a.park;copy=0912');
  renderCompare();
  if (!quiet) toast('two copies loaded -- they read identically');
}

// ---------------------------------------------------------------------------
// Explainer cards
// ---------------------------------------------------------------------------

const EXPLAINERS = [
  ['Tags block', 'A complete shadow copy of printable ASCII that renders as nothing and tokenizes as prose.', 'U+E0000-U+E007F'],
  ['Variation selectors', 'Exactly 256 invisible codepoints, one per byte value. Any payload, carried by any character.', 'U+FE00-U+FE0F, U+E0100-U+E01EF'],
  ['Zero-width characters', 'Occupy no space, survive copy-paste. Four of them make a two-bit channel.', 'U+200B-U+200D, U+2060, U+FEFF'],
  ['Bidirectional overrides', 'Displayed order stops matching stored order. Source reviews one way and compiles another.', 'CVE-2021-42574'],
  ['Homoglyphs', 'Letters from other alphabets drawn identically to ASCII. They read the same and compare unequal.', 'Cyrillic, Greek, Armenian, Cherokee'],
  ['Homograph domains', 'A link that reads as one domain and resolves to another. The punycode is what your browser actually visits.', 'IDN / punycode (xn--)'],
  ['ANSI escapes', 'A terminal is a renderer, and renderers can be told to lie. Cursor moves rewrite printed lines.', 'CSI and OSC sequences'],
  ['Noncharacters and PUA', 'Codepoints with no assigned meaning. Parsers disagree about them, which is the point.', 'U+FDD0-U+FDEF, U+E000-U+F8FF'],
  ['Normalisation drift', 'Text that changes when normalised can pass validation in one form and take effect in another.', 'NFC / NFKC'],
  ['Styled-out text', 'display:none, font-size:0, white on white. Not one unusual character, and the page still says two things.', 'inline style, HTML comment'],
  ['Deceptive links', 'A label that names a hostname is a claim about where you are going. Sometimes the target disagrees.', 'label vs. href'],
  ['Image exfiltration', 'Images are fetched with nobody clicking anything, so a query parameter is a way out for an answer.', 'query-string carriers'],
  ['Encoded payloads', 'Base64 survives every keyword search, because none of the keywords are there. Reported only when it decodes to an instruction.', 'base64'],
];

function renderExplain() {
  const frag = document.createDocumentFragment();
  for (const [title, body, cps] of EXPLAINERS) {
    const card = document.createElement('div');
    card.className = 'card';
    const h = document.createElement('h3');
    h.textContent = title;
    const p = document.createElement('p');
    p.textContent = body;
    const code = document.createElement('span');
    code.className = 'cp';
    code.textContent = cps;
    card.append(h, p, code);
    frag.appendChild(card);
  }
  el.explain.replaceChildren(frag);
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

el.input.addEventListener('input', () => {
  for (const b of el.specimens.children) b.setAttribute('aria-pressed', 'false');
  scheduleUpdate();
});

$('clear').addEventListener('click', () => setInput(''));

$('paste').addEventListener('click', async () => {
  try {
    const text = await navigator.clipboard.readText();
    setInput(text);
    toast('pasted ' + num([...text].length) + ' characters');
  } catch {
    el.input.focus();
    toast('your browser wants you to paste it yourself -- Ctrl+V');
  }
});

$('copy').addEventListener('click', () => copy(cleaned().text, 'cleaned text copied'));

$('replace').addEventListener('click', () => {
  const result = cleaned();
  setInput(result.text);
  toast('removed ' + num(result.removed) + ' characters');
});

$('report').addEventListener('click', () => {
  download('secondsight-report.md', buildReport());
  toast('report downloaded');
});

for (const id of ['opt-hidden', 'opt-ansi', 'opt-spaces', 'opt-fold']) {
  $(id).addEventListener('change', updateCleanSummary);
}

el.spectrum.addEventListener('mousemove', spectrumHover);
el.spectrum.addEventListener('mouseleave', () => { el.spectrumReadout.textContent = ''; });

el.labInput.addEventListener('input', updateLab);
el.labCover.addEventListener('input', updateLab);
el.labScheme.addEventListener('change', updateLab);
$('lab-copy').addEventListener('click', () => copy(el.labOutput.value, 'copied -- most of it is invisible'));
$('lab-send').addEventListener('click', () => {
  setInput(el.labOutput.value);
  ensureVisible(el.inputBlock, { force: true });
});

// The hero button promises the input box, not the top edge of a section that
// happens to contain one. Land on the block, then focus without a second jump.
for (const link of document.querySelectorAll('[data-scroll]')) {
  link.addEventListener('click', (e) => {
    e.preventDefault();
    const target = $(link.dataset.scroll);
    if (!target) return;
    history.replaceState(null, '', '#' + link.dataset.scroll);
    // Focus first: taking focus mid-animation cuts a smooth scroll short, and
    // the reader ends up a few pixels from where they started.
    el.input.focus({ preventScroll: true });
    target.scrollIntoView({ block: 'start', behavior: 'smooth' });
  });
}

// Compare ----------------------------------------------------------------

el.cmpA.addEventListener('input', scheduleCompare);
el.cmpB.addEventListener('input', scheduleCompare);
$('cmp-demo').addEventListener('click', () => loadCompareDemo());

// Comparing two documents usually means comparing two files, so each side
// takes a drop of its own. Same rule as the analyser: the file is read here.
for (const [box, label] of [[el.cmpA, 'A'], [el.cmpB, 'B']]) {
  box.addEventListener('dragover', (e) => e.preventDefault());
  box.addEventListener('drop', async (e) => {
    const file = e.dataTransfer?.files?.[0];
    if (!file) return;
    e.preventDefault();
    if (file.size > 4 * 1024 * 1024) { toast('file is too large -- 4 MB limit'); return; }
    box.value = await file.text();
    renderCompare();
    toast('copy ' + label + ': ' + file.name + ' -- it never left this tab');
  });
}
$('cmp-swap').addEventListener('click', () => {
  const held = el.cmpA.value;
  el.cmpA.value = el.cmpB.value;
  el.cmpB.value = held;
  renderCompare();
});
$('cmp-clear').addEventListener('click', () => {
  el.cmpA.value = '';
  el.cmpB.value = '';
  renderCompare();
});

// File drop -------------------------------------------------------------

['dragenter', 'dragover'].forEach((type) => {
  el.inputBlock.addEventListener(type, (e) => {
    e.preventDefault();
    el.inputBlock.classList.add('dragging');
  });
});
['dragleave', 'drop'].forEach((type) => {
  el.inputBlock.addEventListener(type, (e) => {
    e.preventDefault();
    if (type === 'dragleave' && el.inputBlock.contains(e.relatedTarget)) return;
    el.inputBlock.classList.remove('dragging');
  });
});
el.inputBlock.addEventListener('drop', async (e) => {
  const file = e.dataTransfer?.files?.[0];
  if (!file) return;
  if (file.size > 4 * 1024 * 1024) { toast('file is too large -- 4 MB limit'); return; }
  setInput(await file.text());
  toast('read ' + file.name + ' -- it never left this tab');
});

// Theme ------------------------------------------------------------------

const storedTheme = (() => {
  try { return localStorage.getItem('secondsight-theme'); } catch { return null; }
})();
if (storedTheme) document.documentElement.dataset.theme = storedTheme;

$('theme').addEventListener('click', () => {
  const now = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = now;
  try { localStorage.setItem('secondsight-theme', now); } catch { /* private mode */ }
  renderSpectrum(current);
});

window.addEventListener('resize', () => renderSpectrum(current));

// Start ------------------------------------------------------------------

renderGallery();
renderExplain();
renderLab();
// The comparison starts full for the same reason the analyser does: two empty
// boxes explain nothing, and this one has to be seen working to be understood.
loadCompareDemo({ quiet: true });

const fromHash = specimenById(location.hash.slice(1));
if (fromHash) {
  setInput(fromHash.build(), { markSpecimen: fromHash.id });
  showWhy(fromHash);
} else {
  const opener = specimenById('pr-comment');
  setInput(opener.build(), { markSpecimen: opener.id });
  showWhy(opener);
}
