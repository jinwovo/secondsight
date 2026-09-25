/**
 * secondsight -- text hidden by markup rather than by codepoint
 *
 * The rest of this engine asks whether a character is invisible. That is only
 * one way to hide a sentence from a person and leave it in front of a model.
 * The others are older and, in the wild, more common:
 *
 *   - a paragraph styled `display:none` or white-on-white, which a browser
 *     drops and a scraper, a summariser and an ATS all read in full
 *   - an HTML comment, which renders nowhere and tokenizes like any other text
 *   - a link whose label says one domain and whose target is another
 *   - an image whose URL is a collection endpoint with a slot for your data
 *   - a base64 blob that unpacks into instructions
 *
 * None of these involve a single unusual codepoint, so a character-level
 * scanner walks straight past them. They belong here for the same reason the
 * Tags block does: the reader and the machine are being shown two different
 * documents.
 *
 * This file finds and extracts. It does not decide severity or write prose --
 * detect.js owns that, so every finding in the program is built in one place.
 *
 * Zero dependencies. Pure ASCII source.
 */

import { isAddressed, isPointed } from './decode.js';

// ---------------------------------------------------------------------------
// Text hidden by styling
// ---------------------------------------------------------------------------

/**
 * Styles that remove content from the page while leaving it in the document.
 *
 * Split by confidence rather than lumped together, because these are not
 * equally damning. `display:none` on a block of prose has one purpose. White
 * text, on the other hand, only hides on a white background -- true almost
 * always, but not something this file can actually verify, and a scanner that
 * states more than it knows is a scanner that gets ignored.
 *
 * Each pattern runs against a normalised declaration block (see cssText), and
 * every property is anchored to the start of a declaration: `color` must not
 * match `background-color`, and `height` must not match `line-height`. A value
 * may carry `!important`, which only makes the hiding more deliberate.
 */
const DECL = '(?:^|;)\\s*';
const END = '\\s*(?:!\\s*important\\s*)?(?:;|$)';
const HIDING_RULES = [
  [new RegExp(DECL + 'display\\s*:\\s*none' + END, 'i'), 'display:none', 'certain'],
  [new RegExp(DECL + 'visibility\\s*:\\s*(?:hidden|collapse)' + END, 'i'), 'visibility:hidden', 'certain'],
  [new RegExp(DECL + 'opacity\\s*:\\s*(?:0*\\.?0+|0+%)' + END, 'i'), 'opacity:0', 'certain'],
  [new RegExp(DECL + 'font-size\\s*:\\s*0*\\.?0+(?:px|pt|em|rem|%)?' + END, 'i'), 'font-size:0', 'certain'],
  [new RegExp(DECL + '(?:[a-z-]*left|top|text-indent)\\s*:\\s*-\\s*\\d{3,}\\s*(?:px|em|rem)', 'i'), 'pushed off-screen', 'certain'],
  [new RegExp(DECL + 'clip(?:-path)?\\s*:\\s*(?:rect\\s*\\(\\s*0|inset\\s*\\(\\s*(?:100|50)%)', 'i'), 'clipped to nothing', 'certain'],
  [new RegExp(DECL + '(?:max-)?height\\s*:\\s*0(?:px)?' + END + '[^]*' + DECL + 'overflow\\s*:\\s*hidden', 'i'), 'zero height', 'certain'],
  [new RegExp(DECL + 'color\\s*:\\s*(?:#fff(?:fff)?\\b|white\\b|rgba?\\(\\s*255\\s*,\\s*255\\s*,\\s*255|transparent\\b)', 'i'),
    'white or transparent text', 'likely'],
];

const TAG_OPEN = /<([a-z][a-z0-9]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/gi;
const VOID_TAGS = /^(?:br|hr|img|input|meta|link|source|track|wbr|area|base|col|embed|param)$/i;

const NAMED_ENTITIES = {
  nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
  colon: ':', semi: ';', num: '#', period: '.', sol: '/', bsol: '\\',
};

/** Undo the character references a browser resolves inside an attribute. */
function decodeEntities(s) {
  return s.replace(/&(?:#x([0-9a-f]{1,6})|#(\d{1,7})|([a-z]{2,8}));?/gi, (whole, hex, dec, name) => {
    if (hex || dec) {
      const cp = hex ? parseInt(hex, 16) : parseInt(dec, 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : whole;
    }
    return NAMED_ENTITIES[name.toLowerCase()] ?? whole;
  });
}

/**
 * CSS as a browser reads it, not as it was typed.
 *
 * `display:/* *\/none`, `displ\61 y:none` and, inside a style attribute,
 * `display&#58;none` are all `display:none` to the renderer. A pattern that
 * only knows the plain spelling is a pattern with a documented way around it,
 * so comments go and escapes resolve before any rule is tested.
 */
function cssText(s) {
  return String(s)
    .replace(/\/\*[\s\S]*?(?:\*\/|$)/g, '')
    .replace(/\\([0-9a-f]{1,6})\s?/gi, (whole, hex) => {
      const cp = parseInt(hex, 16);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    })
    .replace(/\\(.)/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * White text is only hidden on a white page. A rule that sets its own dark
 * background -- a button, a banner, a dark theme -- is showing its text, not
 * hiding it. So is transparent text clipped to a gradient background, which is
 * how every gradient heading on the web is drawn.
 */
const LIGHT = '(?:#fff(?:fff)?\\b|white\\b|transparent\\b|none\\b|rgba?\\(\\s*255\\s*,\\s*255\\s*,\\s*255|inherit\\b|initial\\b|unset\\b)';
const OWN_BACKGROUND = new RegExp(DECL + 'background(?:-color|-image)?\\s*:\\s*(?!' + LIGHT + ')\\S', 'i');
const CLIPPED_TO_TEXT = new RegExp(DECL + '(?:-webkit-)?background-clip\\s*:\\s*text', 'i');

function paintsItsOwnBackground(declarations) {
  return OWN_BACKGROUND.test(declarations) || CLIPPED_TO_TEXT.test(declarations);
}

/** The first hiding rule a declaration block trips, or null. */
function hidingIn(declarations) {
  for (const [re, how, confidence] of HIDING_RULES) {
    if (!re.test(declarations)) continue;
    if (how === 'white or transparent text' && paintsItsOwnBackground(declarations)) continue;
    return { how, confidence };
  }
  return null;
}

function attrOf(attrs, name) {
  const m = new RegExp('(?:^|\\s)' + name + '\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))', 'i').exec(attrs);
  return m ? decodeEntities(m[1] ?? m[2] ?? m[3]) : null;
}

/** Strip tags and collapse whitespace, so the extract reads as what it says. */
function plainText(html) {
  return html
    .replace(/<(style|script)\b[^>]*>[\s\S]*?<\/\s*\1\s*>/gi, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Does this look like something written to be read, rather than interface?
 *
 * The first draft of this detector reported the collapsed panel in this
 * project's own page -- a section holding four checkbox labels -- and that is
 * the exact failure the rest of the engine spends its time avoiding. Hiding
 * part of an interface is ordinary. Hiding a paragraph is not, so the bar is a
 * paragraph: enough words, in sentences.
 */
function readsLikeProse(s) {
  const words = s.split(/\s+/).filter(Boolean);
  return s.length >= 40 && words.length >= 8 && /[.!?][\s"')\]]*(?:\s|$)/.test(s);
}

/**
 * Block contexts whose rules apply to the page a person is looking at.
 *
 * `@media print { .x { display:none } }` hides nothing on screen, and the
 * inside of `@keyframes` or `@font-face` is not a selector at all. The wrappers
 * that merely scope rules -- screen media queries, `@supports`, `@layer`,
 * `@container` -- are transparent.
 */
function appliesOnScreen(prelude) {
  if (/^@media\b/i.test(prelude)) return !/\bprint\b/i.test(prelude) || /\b(?:screen|all)\b/i.test(prelude);
  return /^@(?:supports|layer|container|scope)\b/i.test(prelude);
}

/**
 * The part of a selector that names the element actually being styled.
 *
 * Only a plain compound qualifies: a tag, classes, an id. A selector that
 * depends on state -- `:hover`, `:not(.open)`, `[aria-expanded]`, `::before` --
 * describes a moment or a pseudo-element, not the text sitting in the
 * document, and matching it anyway would report every dropdown on the web. An
 * ancestor in front (`.card .note`) is dropped: the element still carries the
 * class that hides it, and that much the markup can show.
 */
function subjectOf(selector) {
  const last = selector.trim().split(/\s*[\s>+~]\s*/).pop();
  const m = /^([a-z][a-z0-9-]*)?((?:[.#][-_a-z0-9]+)*)$/i.exec(last || '');
  if (!m || (!m[1] && !m[2])) return null;
  const classes = [];
  let id = null;
  for (const part of m[2].match(/[.#][-_a-z0-9]+/gi) || []) {
    if (part[0] === '.') classes.push(part.slice(1));
    else id = part.slice(1);
  }
  return { tag: m[1] ? m[1].toLowerCase() : null, classes, id, text: last };
}

/** Every rule in the document's own <style> blocks that hides what it selects. */
export function hidingStylesheetRules(text) {
  const out = [];
  const block = /<style\b[^>]*>([\s\S]*?)<\/\s*style\s*>/gi;
  let m;
  while ((m = block.exec(text)) !== null) {
    const css = cssText(m[1]);
    const stack = [];
    let buf = '';
    for (const ch of css) {
      if (ch === '{') {
        stack.push(buf.trim());
        buf = '';
      } else if (ch === '}') {
        const prelude = stack.pop();
        if (prelude && !prelude.startsWith('@') && stack.every(appliesOnScreen)) {
          const hiding = hidingIn(buf.trim());
          // White text in a dark colour scheme is the whole point of one.
          const darkScheme = stack.some((p) => /prefers-color-scheme\s*:\s*dark/i.test(p));
          if (hiding && !(darkScheme && hiding.confidence === 'likely')) {
            for (const sel of prelude.split(',')) {
              const subject = subjectOf(sel);
              if (subject) out.push({ ...hiding, subject });
            }
          }
        }
        buf = '';
      } else {
        buf += ch;
      }
    }
  }
  return out;
}

/**
 * SVG styling written as attributes rather than as CSS.
 *
 * A text element with `opacity="0"` hides exactly what `opacity:0` hides, and an
 * SVG is a file the scan now reads, so the same rules run over the same
 * properties spelled the other way. Fill is only read on text elements: a
 * `fill="none"` on the root of an icon is how icons are drawn, not how
 * sentences are hidden.
 */
const PRESENTATION = ['display', 'visibility', 'opacity', 'font-size'];
const SVG_TEXT = /^(?:text|tspan|textpath)$/;

function hidingByAttribute(tag, attrs) {
  const declarations = [];
  for (const name of PRESENTATION) {
    const value = attrOf(attrs, name);
    if (value !== null) declarations.push(name + ':' + value);
  }
  const found = declarations.length ? hidingIn(cssText(declarations.join(';'))) : null;
  if (found) return { ...found, via: found.how.split(':')[0] + ' attribute' };

  if (!SVG_TEXT.test(tag)) return null;
  const fillOpacity = attrOf(attrs, 'fill-opacity');
  if (fillOpacity !== null && /^\s*0*\.?0+\s*$/.test(fillOpacity) && !attrOf(attrs, 'stroke')) {
    return { how: 'fill-opacity:0', confidence: 'certain', via: 'fill-opacity attribute' };
  }
  const fill = attrOf(attrs, 'fill');
  if (fill !== null && /^\s*(?:none|transparent)\s*$/i.test(fill) && !attrOf(attrs, 'stroke')) {
    return { how: 'no fill', confidence: 'certain', via: 'fill attribute' };
  }
  if (fill !== null && /^\s*(?:#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*$/i.test(fill)) {
    return { how: 'white or transparent text', confidence: 'likely', via: 'fill attribute' };
  }
  return null;
}

function matchesSubject(subject, tag, classes, id) {
  if (subject.tag && subject.tag !== tag) return false;
  if (subject.id && subject.id !== id) return false;
  return subject.classes.every((c) => classes.has(c));
}

/**
 * Where an element ends, counting nested elements of the same name.
 *
 * Stopping at the first closing tag of the same name is a way around the
 * check, not a simplification of it: a hidden div holding an empty div and
 * then the payload would leave the payload outside the extract. So the scan
 * keeps a depth.
 */
function closingOf(text, from, tag) {
  const re = new RegExp('<(/?)\\s*' + tag + '(?![a-z0-9-])(?:"[^"]*"|\'[^\']*\'|[^>"\'])*>', 'gi');
  re.lastIndex = from;
  let depth = 1;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (m[1]) {
      if (--depth === 0) return m.index;
    } else if (!/\/\s*>$/.test(m[0])) {
      depth++;
    }
  }
  return -1;
}

/**
 * Elements whose content is styled out of the rendered page.
 *
 * Two sources of styling are read: the element's own `style` attribute, and
 * the rules in the document's `<style>` blocks whose selector matches it by
 * tag, class or id. Linked stylesheets are not fetched -- nothing here makes a
 * network request -- and selectors that depend on state or on the shape of the
 * tree are not resolved. Each extract names the rule that did the hiding, so a
 * reader can check it rather than take it on trust.
 */
export function findStyledHidden(text) {
  const out = [];
  const sheet = /<style\b/i.test(text) ? hidingStylesheetRules(text) : [];
  let coveredUntil = -1;

  TAG_OPEN.lastIndex = 0;
  let m;
  while ((m = TAG_OPEN.exec(text)) !== null) {
    const [whole, rawTag, attrs] = m;
    if (VOID_TAGS.test(rawTag) || m.index < coveredUntil) continue;
    const tag = rawTag.toLowerCase();
    if (tag === 'style' || tag === 'script') continue;

    // The `hidden` attribute is deliberately not a trigger. It is the standard,
    // semantic way to toggle a piece of interface, which makes it the emoji
    // joiner of HTML: common, correct, and useless as a signal.
    const style = attrOf(attrs, 'style');
    let hiding = style ? hidingIn(cssText(style)) : null;
    let via = null;
    if (!hiding) {
      hiding = hidingByAttribute(tag, attrs);
      if (hiding) via = hiding.via;
    }
    if (!hiding && sheet.length) {
      const classes = new Set((attrOf(attrs, 'class') || '').split(/\s+/).filter(Boolean));
      const id = attrOf(attrs, 'id');
      const rule = sheet.find((r) => matchesSubject(r.subject, tag, classes, id));
      if (rule) { hiding = rule; via = rule.subject.text; }
    }
    if (!hiding) continue;

    const bodyStart = m.index + whole.length;
    const close = closingOf(text, bodyStart, tag);
    const bodyEnd = close >= 0 ? close : Math.min(text.length, bodyStart + 4000);
    const content = plainText(text.slice(bodyStart, bodyEnd));
    if (!readsLikeProse(content)) continue;

    // Everything inside is already in this extract. A hidden child of a hidden
    // parent is the same text, not a second finding.
    coveredUntil = bodyEnd;
    out.push({
      start: m.index,
      end: bodyEnd,
      tag,
      how: hiding.how,
      confidence: hiding.confidence,
      via,
      text: content,
    });
  }
  return out;
}

/**
 * Comments that read like instructions.
 *
 * A comment is not suspicious. A comment is the normal way to leave a note in
 * a file. What is suspicious is a comment addressed to a language model, so
 * this only reports the ones addressed to one -- an override, a persona, a
 * request to hide or to send something. A licence URL or a mention of `rm -rf`
 * in a note is a note. The caller passes the intent reader in, and decode.js
 * decides which intents count as addressed, so what an instruction looks like
 * is decided in one place, not scattered across two files.
 *
 * Two syntaxes. An HTML comment, and Markdown's own idiom for one: a link
 * reference definition that nothing refers to, `[//]: # (like this)`. A
 * definition renders nowhere whatever it says -- its label, its target and its
 * title all vanish from the page -- which is exactly why READMEs and SKILL.md
 * files use it for notes, and exactly why it is worth reading.
 */
export function findLoadedComments(text, readIntent) {
  const out = [];
  const push = (start, end, kind, body) => {
    if (body.length < 12) return;
    const intents = readIntent(body);
    if (isAddressed(intents)) out.push({ start, end, kind, text: body, intents });
  };

  const html = /<!--([\s\S]{0,4000}?)-->/g;
  let m;
  while ((m = html.exec(text)) !== null) {
    push(m.index, m.index + m[0].length, 'html', plainText(m[1]));
  }

  // label, destination, then an optional title in "", '' or (), which may run
  // onto the next line. The label only counts as hidden text when the target
  // is a placeholder (`#`, `<>`, `//`) -- that is the comment idiom; otherwise
  // it is the name of a real link, and only the title is unseen.
  const definition = /^ {0,3}\[([^\]\n]{1,400})\]:[ \t]*(<[^>\n]*>|\S+)(?:[ \t]*\n?[ \t]*("([^"]{0,4000})"|'([^']{0,4000})'|\(([^()]{0,4000})\)))?[ \t]*$/gm;
  while ((m = definition.exec(text)) !== null) {
    const [whole, label, target, , double, single, paren] = m;
    const title = double ?? single ?? paren ?? '';
    const placeholder = /^(?:#|<>|<#>|\/\/)$/.test(target);
    const body = [placeholder ? label : '', title]
      .filter((s) => s && !/^(?:\/\/|comment|_|#)$/i.test(s.trim()))
      .join(' ')
      .replace(/\s+/g, ' ')
      .trim();
    push(m.index, m.index + whole.length, 'markdown', body);
  }
  return out.sort((a, b) => a.start - b.start);
}

// ---------------------------------------------------------------------------
// Links that do not go where they read
// ---------------------------------------------------------------------------

/**
 * A hostname sitting in a piece of visible text.
 *
 * Deliberately narrow. `[SARIF 2.1.0](https://sarifweb...)` is not a link
 * pretending to be somewhere else, and `[README.md](https://github.com/...)`
 * is not either -- but ".md" is Moldova and ".rs" is Serbia, so a rule that
 * accepts any dotted token as a hostname turns every filename in every
 * markdown file into a phishing alert.
 *
 * So a label counts as naming a destination only when it says so plainly --
 * it carries a scheme or a www -- or when it ends in one of a short list of
 * web TLDs that nobody uses as a file extension.
 */
const LABEL_TLDS = 'com|net|org|edu|gov|mil|int|io|dev|app|ai|co|xyz|info|biz'
  + '|cloud|shop|store|online|site|tv|gg|link|page|news|blog|wiki|tech|bank';
const EXPLICIT_HOST = /(?:https?:\/\/|\bwww\.)((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24})/i;
const BARE_HOST = new RegExp(
  '(?:^|[\\s(<"\'])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:' + LABEL_TLDS + '))(?![a-z0-9-])',
  'i',
);

function hostInLabel(label) {
  const explicit = EXPLICIT_HOST.exec(label);
  if (explicit) return explicit[1];
  const bare = BARE_HOST.exec(label);
  return bare ? bare[1] : null;
}

/**
 * Suffixes under which anyone can register a name, so the site is the label
 * in front of them. Without this, `bbc.co.uk` and `evil.co.uk` are both just
 * "co.uk", and a link from one to the other passes as a link to itself. Not
 * the whole Public Suffix List -- the country suffixes people actually spoof,
 * and the hosting platforms where every subdomain is a different owner.
 */
const SHARED_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'gov.au',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'co.kr', 'or.kr', 'ac.kr', 'go.kr', 'com.cn', 'net.cn',
  'com.tw', 'com.hk', 'com.sg', 'co.in', 'co.nz', 'co.za', 'com.br', 'com.mx', 'com.ar',
  'com.tr', 'co.il', 'co.id', 'com.my', 'com.ph', 'com.vn',
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
  'herokuapp.com', 'blogspot.com', 'web.app', 'firebaseapp.com', 'azurewebsites.net',
  'cloudfront.net', 'ngrok.io', 'ngrok-free.app', 'glitch.me', 'repl.co', 's3.amazonaws.com',
]);

/**
 * Link shorteners run by the site they point into. `aka.ms` is Microsoft's,
 * and Microsoft's own SECURITY.md template -- in thousands of repositories --
 * labels an aka.ms link as msrc.microsoft.com. That is one owner under two
 * names, not a label lying about a destination. Kept short and first-party
 * only: bit.ly and friends belong to nobody in particular, so they stay out.
 */
const SAME_OWNER = new Map([
  ['aka.ms', 'microsoft.com'], ['youtu.be', 'youtube.com'], ['goo.gl', 'google.com'],
  ['g.co', 'google.com'], ['git.io', 'github.com'], ['amzn.to', 'amazon.com'],
  ['fb.me', 'facebook.com'], ['lnkd.in', 'linkedin.com'], ['t.co', 'x.com'],
  ['twitter.com', 'x.com'], ['redd.it', 'reddit.com'], ['wp.me', 'wordpress.com'],
]);

/** The registrable part of a hostname: enough to tell github from evil. */
function registrable(host) {
  const parts = String(host).toLowerCase().replace(/\.$/, '').split('.');
  const lastTwo = parts.slice(-2).join('.');
  const site = SHARED_SUFFIXES.has(lastTwo) || SHARED_SUFFIXES.has(parts.slice(-3).join('.'))
    ? parts.slice(SHARED_SUFFIXES.has(parts.slice(-3).join('.')) ? -4 : -3).join('.')
    : lastTwo;
  return SAME_OWNER.get(site) || site;
}

function hostOf(url) {
  const m = /^\s*(?:https?:)?\/\/(?:[^/@\s]*@)?([^/?#\s:]+)/i.exec(url);
  return m ? m[1].toLowerCase() : null;
}

/**
 * A label that names a destination, next to a target that is somewhere else.
 *
 * Only labels that themselves look like a hostname count. "Click here"
 * pointing anywhere is a link; "github.com" pointing at another domain is a
 * claim about where you are going, and it is false.
 */
export function findDeceptiveLinks(text) {
  const out = [];
  const push = (start, end, kind, label, href) => {
    // A logo in the label is a picture of somewhere, not a claim about where
    // the link goes: `[<img src="https://a.com/logo.png">](https://b.org)` is a
    // sponsor badge. Only text a reader sees can make the claim.
    const shown = hostInLabel(plainText(label.replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')));
    if (!shown) return;
    const target = hostOf(href);
    if (!target) return;
    if (registrable(shown) === registrable(target)) return;
    out.push({ start, end, kind, label: shown, href, target, sample: shown + '  ->  ' + target });
  };

  const md = /\[([^\]\n]{1,200})\]\(\s*<?([^)\s>]+)>?\s*(?:"[^"]*")?\s*\)/g;
  let m;
  while ((m = md.exec(text)) !== null) {
    // An image is not a link, and a label that opens with one is a badge the
    // pattern has cut in half -- `[![alt](img)](href)` pairs the alt text
    // with the image URL. The rule stays with whole links it can read.
    if (text[m.index - 1] === '!' || m[1].startsWith('![')) continue;
    push(m.index, m.index + m[0].length, 'markdown', m[1], m[2]);
  }

  const anchor = /<a\b((?:"[^"]*"|'[^']*'|[^>"'])*)>([\s\S]{0,400}?)<\/\s*a\s*>/gi;
  while ((m = anchor.exec(text)) !== null) {
    const href = /href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(m[1]);
    if (!href) continue;
    push(m.index, m.index + m[0].length, 'html', plainText(m[2]), href[1] ?? href[2] ?? href[3]);
  }
  return out;
}

/** Hrefs that are not addresses at all but code or inline payloads. */
export function findExecutableHrefs(text) {
  const out = [];
  const re = /(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)')|\]\(\s*(javascript:|data:|vbscript:)([^)\s]*)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const value = m[1] ?? m[2] ?? ((m[3] || '') + (m[4] || ''));
    if (!/^\s*(?:javascript|vbscript|data)\s*:/i.test(value)) continue;
    const scheme = /^\s*([a-z]+)\s*:/i.exec(value)[1].toLowerCase();
    // A data: image in an href is a picture, not a program.
    if (scheme === 'data' && /^\s*data\s*:\s*image\//i.test(value)) continue;
    // `javascript:void(0)` is the old idiom for a link that does nothing, and
    // it is all over documentation. A program that returns nothing is not one.
    if (scheme === 'javascript' && /^\s*javascript\s*:\s*(?:void\s*\(?\s*0\s*\)?)?\s*;?\s*$/i.test(value)) continue;
    out.push({
      start: m.index, end: m.index + m[0].length, scheme,
      sample: value.replace(/\s+/g, ' ').slice(0, 90),
    });
  }
  return out;
}

// Parameter names that exist to carry a value out rather than to fetch one in.
const CARRIER_PARAMS = /\b(?:data|payload|content|prompt|context|secret|token|apikey|api_key|key|exfil|leak|dump|body|msg|message|note|text|input|out|log|capture)\b/i;

/**
 * Images whose URL is a collection endpoint.
 *
 * This is the standard way a hidden instruction gets its answer back out: the
 * model is told to fill a value into an image URL, and the browser or the
 * agent fetches it without anyone clicking anything. A remote image is
 * ordinary, so the signal is not the host -- it is a query string with a slot
 * in it, especially one that is still empty or still a placeholder.
 */
export function findExfilImages(text) {
  const out = [];
  const push = (start, end, url) => {
    const q = url.indexOf('?');
    if (q < 0) return;
    const query = url.slice(q + 1);
    // Parameter names, not values: a badge's `logo=data:image/svg+xml` has the
    // word "data" in it and carries nothing anywhere.
    const names = query.split('&').map((pair) => pair.split('=')[0]).join(' ');
    if (!CARRIER_PARAMS.test(names)) return;
    const host = hostOf(url);
    if (!host) return;
    const empty = /=(?:$|&)/.test(query);
    const placeholder = /[{<[]\s*[a-z_ ]{2,30}\s*[}>\]]/i.test(query) || /\bYOUR_|\bINSERT|\bPUT_/i.test(query);
    out.push({
      start, end, host, empty, placeholder,
      sample: url.replace(/\s+/g, '').slice(0, 110),
    });
  };

  let m;
  const mdImage = /!\[[^\]\n]{0,200}\]\(\s*<?([^)\s>]+)>?\s*(?:"[^"]*")?\s*\)/g;
  while ((m = mdImage.exec(text)) !== null) push(m.index, m.index + m[0].length, m[1]);

  const htmlImage = /<img\b((?:"[^"]*"|'[^']*'|[^>"'])*)>/gi;
  while ((m = htmlImage.exec(text)) !== null) {
    const src = /src\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(m[1]);
    if (src) push(m.index, m.index + m[0].length, src[1] ?? src[2] ?? src[3]);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Text encoded rather than hidden
// ---------------------------------------------------------------------------

const BASE64_RUN = /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

function decodeBase64(chunk) {
  try {
    const binary = atob(chunk);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Base64 runs that unpack into instructions.
 *
 * Base64 is everywhere -- keys, hashes, inline images, lockfile integrity
 * fields -- so decoding one proves nothing on its own and reporting every
 * successful decode would bury the page in noise. A run is only reported when
 * it turns into readable text *and* that text reads as an instruction or a
 * command -- not merely a URL or the word "password", which is what a decoded
 * config or token looks like. That is the one case where the encoding was the
 * point.
 */
export function findEncodedInstructions(text, readIntent, isPlausibleText) {
  const out = [];
  BASE64_RUN.lastIndex = 0;
  let m;
  while ((m = BASE64_RUN.exec(text)) !== null) {
    const chunk = m[0];
    if (chunk.length > 8000) continue;
    // The body of a `data:image/...;base64,` URI is a picture. An inline SVG
    // decodes to markup, which is not an instruction for being markup.
    if (/data:image\/[a-z0-9.+-]+;base64,$/i.test(text.slice(Math.max(0, m.index - 64), m.index))) continue;
    const decoded = decodeBase64(chunk);
    if (!decoded || !isPlausibleText(decoded, 16)) continue;
    const intents = readIntent(decoded);
    if (!isPointed(intents)) continue;
    out.push({
      start: m.index, end: m.index + chunk.length,
      encoded: chunk.slice(0, 60), decoded, intents,
    });
  }
  return out;
}
