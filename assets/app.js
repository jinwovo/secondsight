/* secondsight -- interface
 *
 * Everything runs here, in this tab. The page makes no network request after
 * it loads, which is the point: the text you would most want to check is the
 * text you would least want to upload.
 */

import { analyze, visibleText, humanText, SEVERITY } from '../src/detect.js';
import { sanitize } from '../src/sanitize.js';
import { SPECIMENS, specimenById } from '../src/specimens.js';
import { SCHEMES } from '../src/encode.js';
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
};

// The machine pane renders one node per codepoint. Past a few thousand that
// stops being informative and starts being a scroll bar, so it is capped and
// the cap is stated rather than hidden.
const RENDER_CAP = 3000;

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
      + (s.hidden ? '  ·  ' + num(s.hidden) + ' invisible' : '')
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
      count.textContent = num(f.count) + ' characters';
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

    if (f.positions.length) {
      card.style.cursor = 'pointer';
      card.title = 'Jump to the first one';
      card.addEventListener('click', () => {
        const target = el.machine.querySelector('[data-offset="' + f.positions[0] + '"]');
        if (target) {
          target.scrollIntoView({ block: 'center', behavior: 'smooth' });
          target.animate(
            [{ outline: '2px solid var(--accent)' }, { outline: '2px solid transparent' }],
            { duration: 1300 },
          );
        }
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
  el.cleanSummary.textContent = result.changes.length
    ? result.changes.map((c) => c.label + (c.count > 1 ? ' x' + c.count : '')).slice(0, 3).join(', ')
      + (result.changes.length > 3 ? ', +' + (result.changes.length - 3) + ' more' : '')
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

function renderGallery() {
  const frag = document.createDocumentFragment();
  for (const s of SPECIMENS) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'specimen' + (s.id === 'clean' ? ' control' : '');
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
      el.input.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    });
    frag.appendChild(button);
  }
  el.specimens.replaceChildren(frag);
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
// Explainer cards
// ---------------------------------------------------------------------------

const EXPLAINERS = [
  ['Tags block', 'A complete shadow copy of printable ASCII that renders as nothing and tokenizes as prose.', 'U+E0000-U+E007F'],
  ['Variation selectors', 'Exactly 256 invisible codepoints, one per byte value. Any payload, carried by any character.', 'U+FE00-U+FE0F, U+E0100-U+E01EF'],
  ['Zero-width characters', 'Occupy no space, survive copy-paste. Four of them make a two-bit channel.', 'U+200B-U+200D, U+2060, U+FEFF'],
  ['Bidirectional overrides', 'Displayed order stops matching stored order. Source reviews one way and compiles another.', 'CVE-2021-42574'],
  ['Homoglyphs', 'Letters from other alphabets drawn identically to ASCII. They read the same and compare unequal.', 'Cyrillic, Greek, Armenian, Cherokee'],
  ['ANSI escapes', 'A terminal is a renderer, and renderers can be told to lie. Cursor moves rewrite printed lines.', 'CSI and OSC sequences'],
  ['Noncharacters and PUA', 'Codepoints with no assigned meaning. Parsers disagree about them, which is the point.', 'U+FDD0-U+FDEF, U+E000-U+F8FF'],
  ['Normalisation drift', 'Text that changes when normalised can pass validation in one form and take effect in another.', 'NFC / NFKC'],
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
  el.input.scrollIntoView({ block: 'center', behavior: 'smooth' });
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

const fromHash = specimenById(location.hash.slice(1));
if (fromHash) {
  setInput(fromHash.build(), { markSpecimen: fromHash.id });
  showWhy(fromHash);
} else {
  const opener = specimenById('pr-comment');
  setInput(opener.build(), { markSpecimen: opener.id });
  showWhy(opener);
}
