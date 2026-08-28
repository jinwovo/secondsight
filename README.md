# secondsight

[![ci](https://github.com/jinwovo/secondsight/actions/workflows/ci.yml/badge.svg)](https://github.com/jinwovo/secondsight/actions/workflows/ci.yml)
[![live demo](https://img.shields.io/badge/demo-jinwovo.github.io-4ec9d9)](https://jinwovo.github.io/secondsight/)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-3fb950)](https://github.com/jinwovo/secondsight/blob/main/package.json)
[![license](https://img.shields.io/badge/license-MIT-blue)](https://github.com/jinwovo/secondsight/blob/main/LICENSE)

**See what the machine sees.** A microscope for the characters hiding in text -- the ones your eyes, your editor, and your diff all agree aren't there, and the tokenizer reads anyway.

Paste anything and the screen splits in two: what **you** see, and what the **machine** sees. When those two readings disagree, something is hidden -- and secondsight decodes it, names it, and tells you what it says.

**[Open it ->](https://jinwovo.github.io/secondsight/)**  |  no install, no upload, no network request after the page loads.

<p align="center">
  <img src="docs/demo.gif" alt="secondsight decoding hidden Unicode across five real attacks -- Tags-block smuggling, a variation-selector payload in one emoji, a Trojan Source bidi override, a homoglyph install command, and a clean control specimen it correctly leaves alone" width="840">
</p>

<p align="center"><sub>Five specimens. The same engine decodes each one, shows the two readings, and stays silent on the control.</sub></p>

---

## Why this exists

Every piece of text now has two readers. You are one of them. The other is whatever language model summarises your pull requests, triages your issues, or reads your config files at startup -- and it reads every character you cannot see.

Those characters are real, standardised, and already being used:

- The **Tags block** (`U+E0000`-`U+E007F`) is a complete shadow copy of printable ASCII. It renders as *nothing* -- not in GitHub, not in your terminal, not in your editor -- and tokenizes as ordinary prose. A one-line PR comment can carry a paragraph of instructions only the model will read.
- **Variation selectors** are invisible by design, and there are exactly 256 of them -- one per byte value. Hang them off a single emoji and it carries a payload of unlimited length through every "plain text" channel you have.
- A **right-to-left override** (`U+202E`) reorders the text a human reads without touching the bytes a compiler reads. Source code reviews one way and compiles another. This is [Trojan Source, CVE-2021-42574](https://trojansource.codes/), and it shipped in real projects before it had a name.
- **Homoglyphs** clone a package name or a domain in an alphabet that reads identically to Latin and compares unequal to it.

In 2026, [Snyk found prompt injection in 36% of the agent skills it surveyed](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/). The attacks are here. Most tools respond by printing a warning like *"76 invisible characters detected."* That is the easy half and the useless half. **secondsight shows you the two readings side by side, then tells you what the hidden half actually says.**

## What makes it different

Plenty of tools can count zero-width characters. The hard parts -- the parts most tools skip -- are the ones that make this trustworthy:

| | most scanners | secondsight |
|---|---|---|
| Output | "N invisible characters" | the two readings, side by side, **plus the decoded payload** |
| Tags / variation selectors / zero-width | flagged | **decoded back into text** |
| Reads the payload's intent | -- | flags instruction-override, exfiltration, credential paths |
| Korean / Russian / Arabic / emoji | often flagged as suspicious | **left alone, on purpose** |
| Trust check | -- | a **clean control specimen** you can watch it stay silent on |
| Runs on your secrets | uploads to a server | **never leaves your browser** |

That fourth row is the one that matters most. A scanner that cries wolf on ordinary Korean, on a Persian ZWNJ, on an emoji joiner, or on a byte-order mark is a scanner people learn to ignore -- and the day it finds something real, they ignore that too. secondsight demotes every one of those by context, and ships a control specimen precisely so you can confirm it stays quiet.

## Three ways to use it

**In your browser** -- [jinwovo.github.io/secondsight](https://jinwovo.github.io/secondsight/). Paste, drop a file, or click a specimen from the gallery to watch a real attack get built and then taken apart. Nothing you paste is transmitted; there is no backend to transmit it to.

**On the command line** -- same engine, no dependencies, nothing to install:

```bash
# scan a repo, decode anything hidden
npx github:jinwovo/secondsight .

# check a single file, or pipe text in
npx github:jinwovo/secondsight README.md
pbpaste | npx github:jinwovo/secondsight

# strip the hidden characters back out
npx github:jinwovo/secondsight suspicious.md --fix

# machine-readable, for scripts
npx github:jinwovo/secondsight . --json
```

**In CI, as a GitHub Action** -- fail a build when someone slips invisible characters into an instruction file, a lockfile, or a commit. One step, nothing to install:

```yaml
# .github/workflows/secondsight.yml
name: secondsight
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: jinwovo/secondsight@v1
        with:
          paths: '.'          # optional, defaults to the whole repo
          fail-on: high       # info | low | medium | high | critical
```

Or without the Action, on any runner that has Node:

```yaml
      - run: npx github:jinwovo/secondsight . --fail-on high
```

`--fail-on` (and the Action's `fail-on`) takes `info`, `low`, `medium`, `high`, or `critical`. The build fails at or above that level.

## As a library

Zero dependencies, ESM, runs anywhere modern JavaScript runs.

```js
import { analyze } from 'secondsight';

const result = analyze(untrustedText);

result.verdict.label;   // 'CLEAN' | 'MINOR' | 'SUSPICIOUS' | 'DANGEROUS' | 'CRITICAL'
result.stats.hidden;    // count of invisible codepoints (emoji joiners etc. excluded)
result.findings;        // typed findings, each with a decoded payload where one exists

for (const f of result.findings) {
  console.log(f.severity, f.title);
  if (f.decoded) console.log('  hidden text:', f.decoded);
  if (f.intents.length) console.log('  reads as:', f.intents.map(i => i.label));
}
```

Clean it, with a ledger of exactly what changed:

```js
import { sanitize } from 'secondsight/sanitize';

const { text, changes, removed } = sanitize(untrustedText);
// changes: [{ label: 'removed ZWSP', count: 3 }, ...]
```

`sanitize` never touches a character that is doing its job: an emoji joiner, a Persian ZWNJ, and a leading byte-order mark all survive. Confusable-folding is opt-in (`{ foldConfusables: true }`), because rewriting someone's letters is a bigger decision than removing a hidden one.

## What it looks for

Tags block | variation-selector payloads | zero-width steganography (decoded across the common encodings) | bidirectional overrides and isolates (Trojan Source) | ANSI escape sequences that rewrite terminal output | homoglyphs and mixed-script words | full-width and mathematical compatibility forms | Unicode noncharacters and Private Use Area | deprecated format characters | interlinear annotation | stacked combining marks | unusual spaces | normalization drift. Every finding carries its codepoint offsets, and the decoders round-trip against their own encoders in the test suite.

## Honest limitations

- **Intent-reading is a heuristic.** When a decoded payload looks like an instruction rather than a serial number, that is pattern matching, and it is labelled as such in the output. It raises a finding's severity; it never invents one.
- **Zero-width steganography has no single standard.** Known encodings are decoded; anything else is reported as *present but not decoded*, because a confident wrong answer is worse than an honest gap.
- **Homoglyph coverage is the common attack set, not all of Unicode.** Mixed-script detection needs no table and catches the general case; the named lookalike table covers the scripts actually used for spoofing.

## Development

```bash
node --test test/test.js     # 53 tests, zero dependencies
npm run selfcheck            # the tool scans its own source and finds it clean
python -m http.server 8080   # then open http://localhost:8080
```

The source is deliberately pure ASCII, and every codepoint it describes is written as a number rather than as the character itself -- a homoglyph table typed out as glyphs is a table nobody can review. A tool that hunts invisible characters has no business smuggling any through its own source, and `npm run selfcheck` proves it doesn't.

## License

MIT. Use it, fork it, ship it in your pipeline.

---

<sub>The attacks demonstrated here are documented in the Unicode standard and in public security research. secondsight decodes and defends against them; it adds no novel offensive capability. Built to make an invisible problem visible.</sub>
