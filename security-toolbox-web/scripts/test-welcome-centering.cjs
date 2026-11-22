'use strict';
// READ-ONLY static gate for the welcome-screen centring rules.
//
// The welcome screen must stay centred inside the chat canvas while remaining
// scrollable-safe on short windows. This checks that the two rules that make that
// true survive in src/views/Dashboard.vue — and that no later rule re-introduces a
// one-sided top padding that would push the content off centre again.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { parse } = require('@vue/compiler-sfc');

const root = path.resolve(__dirname, '..');
const vueFile = path.join(root, 'src/views/Dashboard.vue');
const source = fs.readFileSync(vueFile, 'utf8');
const { descriptor } = parse(source);
const css = descriptor.styles[0].content;

const ruleBodies = (selector) => {
  const pattern = new RegExp(`(^|\\n)${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{([^}]*)\\}`, 'g');
  return [...css.matchAll(pattern)].map((match) => match[2]);
};

const baseRules = ruleBodies('.chat-welcome');
assert.ok(baseRules.length >= 1, '.chat-welcome rule must exist');
assert.ok(
  baseRules.some((body) => /justify-content:\s*safe\s+center/.test(body)),
  '.chat-welcome must use justify-content: safe center (centred, but never clipped when the window is short)',
);
assert.ok(
  baseRules.some((body) => /align-items:\s*center/.test(body)),
  '.chat-welcome must keep align-items: center for horizontal centring',
);
assert.ok(
  baseRules.some((body) => /overflow:\s*auto/.test(body)),
  '.chat-welcome must keep overflow: auto so a short window can scroll the welcome screen',
);

// The later override declares symmetric padding. Any padding-top with a value
// other than 0 there would offset the vertical centring by half that value.
const paddingTopValues = [...css.matchAll(/(^|\n)\.chat-welcome\s*\{([^}]*)\}/g)]
  .map((match, order) => {
    const body = match[2];
    if (!/padding\s*:/.test(body)) return null;
    const explicit = body.match(/padding-top\s*:\s*([^;]+);/);
    const shorthand = body.match(/padding\s*:\s*([^;]+);/);
    const parts = shorthand ? shorthand[1].trim().split(/\s+/) : [];
    const top = explicit ? explicit[1].trim() : parts[0] || null;
    const bottom = parts.length >= 2 ? parts[parts.length >= 3 ? 2 : 1] : top;
    return top === null ? null : { order, top, bottom };
  })
  .filter(Boolean);
// A large one-sided top padding (the old clamp(44px, 7vh, 86px)) pushes the whole
// block off centre. A small top gap that keeps the icon off the header rule is
// fine as long as it stays symmetric with the bottom padding.
const MAX_TOP_PADDING_PX = 16;
const lastRule = paddingTopValues[paddingTopValues.length - 1];
assert.ok(lastRule, '.chat-welcome must declare padding');
const topPx = parseFloat(lastRule.top);
assert.ok(
  lastRule.top === '0' || lastRule.top === '0px' || (Number.isFinite(topPx) && topPx <= MAX_TOP_PADDING_PX),
  `the effective .chat-welcome rule must not keep a large asymmetric padding-top (found ${lastRule.top}); it offsets the vertical centring`,
);
assert.ok(
  lastRule.bottom === lastRule.top || Math.abs(parseFloat(lastRule.bottom) - topPx) <= 8,
  `.chat-welcome top/bottom padding must stay balanced (found ${lastRule.top} / ${lastRule.bottom})`,
);

console.log(JSON.stringify({
  checked: vueFile,
  rules: baseRules.map((body) => body.replace(/\s+/g, ' ').trim()),
  result: 'welcome centring rules intact',
}, null, 2));

