const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');
const { performance } = require('node:perf_hooks');

const source = path.join(__dirname, '../src/utils/topologyCollision.ts');
const moduleOutput = { exports: {} };
const code = ts.transpileModule(fs.readFileSync(source, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
}).outputText;
vm.runInThisContext(`(function(module,exports){${code}\n})`, { filename: source })(moduleOutput, moduleOutput.exports);
const { resolveTopologyCollisions } = moduleOutput.exports;
const dimensions = { cardWidth: 228, cardHeight: 68, hubWidth: 216, hubHeight: 68 };

function assertSeparated(nodes, hubs = [], fixed = {}, size = dimensions) {
  const nodeX = size.cardWidth + (size.paddingX ?? 26);
  const nodeY = size.cardHeight + (size.paddingY ?? 18);
  const hubX = (size.cardWidth + size.hubWidth) / 2 + (size.hubPaddingX ?? 32);
  const hubY = (size.cardHeight + size.hubHeight) / 2 + (size.hubPaddingY ?? 24);
  const clear = (a, b, x, y) => Math.abs(a.x - b.x) >= x || Math.abs(a.y - b.y) >= y;
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    assert.ok(Number.isFinite(a.x) && Number.isFinite(a.y));
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      if (fixed[a.id] != null && fixed[b.id] != null) continue;
      assert.ok(clear(a, b, nodeX, nodeY), `nodes ${a.id} and ${b.id} overlap`);
    }
    if (fixed[a.id] == null) {
      for (const hub of hubs) assert.ok(clear(a, hub, hubX, hubY), `node ${a.id} overlaps a hub`);
    }
  }
}

let passed = 0;
function test(name, fn) { fn(); passed++; console.log('PASS ' + name); }

test('a single node still avoids a single hub', () => {
  const hubs = [{ x: 0, y: 0 }];
  assertSeparated(resolveTopologyCollisions([{ id: 1, x: 0, y: 0 }], hubs, {}, dimensions), hubs);
});

test('collision separation is pure and preserves unrelated node data', () => {
  const nodes = Object.freeze([
    Object.freeze({ id: 1, x: 0, y: 0, title: 'first' }),
    Object.freeze({ id: 'second', x: 10, y: 10, title: 'second' }),
    Object.freeze({ id: 3, x: 2000, y: -2000, title: 'far' }),
  ]);
  const hubs = Object.freeze([Object.freeze({ x: 0, y: -10 })]);
  const before = JSON.stringify({ nodes, hubs });
  const result = resolveTopologyCollisions(nodes, hubs, Object.freeze({}), dimensions);
  assertSeparated(result, hubs);
  assert.equal(JSON.stringify({ nodes, hubs }), before);
  assert.notEqual(result[0], nodes[0]);
  assert.deepEqual(result.map(node => node.title), ['first', 'second', 'far']);
  assert.deepEqual(result[2], nodes[2]);
  assert.deepEqual(resolveTopologyCollisions(nodes, hubs, {}, dimensions), result);
});

test('custom coordinates remain fixed even when they overlap other fixed nodes and hubs', () => {
  const nodes = [
    { id: 'fixed-a', x: 0, y: 0 },
    { id: 'fixed-b', x: 0, y: 0 },
    ...Array.from({ length: 16 }, (_, id) => ({ id, x: 0, y: 0 })),
  ];
  const fixed = { 'fixed-a': { x: 0, y: 0 }, 'fixed-b': { x: 0, y: 0 } };
  const hubs = [{ x: 0, y: 0 }, { x: 30, y: 10 }];
  const result = resolveTopologyCollisions(nodes, hubs, fixed, dimensions);
  assert.deepEqual(result.slice(0, 2), nodes.slice(0, 2));
  assertSeparated(result, hubs, fixed);
});

test('dense coincident nodes have no residual overlaps after bounded relaxation', () => {
  const nodes = Array.from({ length: 100 }, (_, id) => ({ id, x: -500, y: -500 }));
  const hubs = [{ x: -500, y: -500 }, { x: -300, y: -700 }];
  assertSeparated(resolveTopologyCollisions(nodes, hubs, {}, dimensions), hubs);
});

test('bucket crossings and varied hub sizes retain required safety margins', () => {
  let seed = 17;
  const random = () => { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed / 2 ** 32; };
  const nodes = Array.from({ length: 150 }, (_, id) => ({ id, x: (random() - 0.5) * 5000, y: (random() - 0.5) * 1500 }));
  const hubs = [{ x: 0, y: 0 }, { x: 800, y: -200 }, { x: -600, y: 100 }];
  const size = { ...dimensions, hubWidth: 700, hubHeight: 130, paddingX: 40, hubPaddingY: 35 };
  const fixed = { 7: { x: nodes[7].x, y: nodes[7].y }, 98: { x: nodes[98].x, y: nodes[98].y } };
  const result = resolveTopologyCollisions(nodes, hubs, fixed, size);
  assertSeparated(result, hubs, fixed, size);
  assert.deepEqual(result[7], nodes[7]);
  assert.deepEqual(result[98], nodes[98]);
});

test('already separated nodes at cell boundaries do not drift', () => {
  const nodes = Array.from({ length: 50 }, (_, id) => ({ id, x: (id - 25) * 254, y: 0 }));
  assert.deepEqual(resolveTopologyCollisions(nodes, [], {}, dimensions), nodes);
});

test('large sparse layouts remain unchanged without a quadratic scan', () => {
  const nodes = Array.from({ length: 30000 }, (_, id) => ({ id, x: (id % 500) * 600, y: Math.floor(id / 500) * 220 }));
  const hubs = Array.from({ length: 3000 }, (_, id) => ({ x: (id % 500) * 600, y: -5000 - Math.floor(id / 500) * 220 }));
  const start = performance.now();
  const result = resolveTopologyCollisions(nodes, hubs, {}, dimensions);
  const elapsed = performance.now() - start;
  assert.deepEqual(result, nodes);
  // Deliberately generous: the former all-pairs scan examines over 500 million
  // pairs here even though there are no collisions. Normal bucket runs take ms.
  assert.ok(elapsed < 5000, `sparse layout took ${elapsed.toFixed(0)} ms`);
  console.log(`  30,000 nodes + 3,000 hubs: ${elapsed.toFixed(1)} ms`);
});

console.log(`${passed} topology collision checks passed.`);
