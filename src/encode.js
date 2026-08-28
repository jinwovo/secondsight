/**
 * secondsight -- encoders
 *
 * These build the same payloads the analyzer takes apart. They exist because
 * reading that "the Tags block is invisible" convinces nobody, and watching a
 * sentence you just typed vanish into an emoji convinces everybody.
 *
 * Nothing here is novel or withheld. Every scheme below is documented in the
 * Unicode standard and already shipped in public research tooling; the useful
 * thing this file adds is that the decoder sits right next to it. It powers the
 * gallery specimens and the lab pane, and it is the reason the test suite can
 * round-trip its own attacks.
 *
 * Zero dependencies. Pure ASCII source.
 */

/**
 * Encode ASCII into the Tags block: U+E0000 plus the character's own code.
 * Invisible in every renderer, plain text to a tokenizer.
 */
export function encodeTags(text, { wrap = false } = {}) {
  let out = wrap ? String.fromCodePoint(0xe0001) : '';
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (code >= 0x20 && code <= 0x7e) out += String.fromCodePoint(0xe0000 + code);
  }
  if (wrap) out += String.fromCodePoint(0xe007f);
  return out;
}

/**
 * Encode arbitrary bytes into variation selectors. There are exactly 256 of
 * them, so any byte string fits, and they attach to whatever character comes
 * before them -- traditionally an emoji, which still renders as itself.
 */
export function encodeVariationSelectors(text, carrier = '') {
  const bytes = new TextEncoder().encode(text);
  let out = carrier;
  for (const b of bytes) {
    out += b < 16
      ? String.fromCodePoint(0xfe00 + b)
      : String.fromCodePoint(0xe0100 + b - 16);
  }
  return out;
}

/**
 * Encode bytes as binary using two zero-width characters, MSB first. This is
 * the layout most of the zero-width steganography libraries settle on.
 */
export function encodeZeroWidth(text, zero = 0x200b, one = 0x200c) {
  const bytes = new TextEncoder().encode(text);
  let out = '';
  for (const b of bytes) {
    for (let i = 7; i >= 0; i--) {
      out += String.fromCodePoint(((b >> i) & 1) ? one : zero);
    }
  }
  return out;
}

/**
 * Wrap text in a right-to-left override so it renders reversed while the
 * stored order is unchanged. The primitive behind Trojan Source.
 */
export function encodeBidiOverride(text) {
  return String.fromCodePoint(0x202e) + text + String.fromCodePoint(0x202c);
}

export const SCHEMES = [
  {
    id: 'tags',
    name: 'Unicode Tags block',
    hint: 'One invisible codepoint per ASCII character. Renders as nothing anywhere.',
    encode: (text) => encodeTags(text),
  },
  {
    id: 'variation',
    name: 'Variation selectors',
    hint: 'Any byte string, carried by a single visible character.',
    encode: (text) => encodeVariationSelectors(text, ''),
  },
  {
    id: 'zero-width',
    name: 'Zero-width binary',
    hint: 'Eight zero-width characters per byte.',
    encode: (text) => encodeZeroWidth(text),
  },
  {
    id: 'bidi',
    name: 'Right-to-left override',
    hint: 'Displayed order stops matching stored order.',
    encode: (text) => encodeBidiOverride(text),
  },
];
