import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

class Element {
  textContent = '';
  value = '';
  disabled = false;
  listeners = new Map();
  attributes = new Map();
  classes = new Set();
  children = [];
  classList = { toggle: (name, enabled) => enabled ? this.classes.add(name) : this.classes.delete(name) };
  addEventListener(name, fn) { this.listeners.set(name, fn); }
  setAttribute(name, value) { this.attributes.set(name, value); }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  async trigger(name) { await this.listeners.get(name)?.(); }
}

test('browser module executes actual Web Crypto encryption and rejects tampering', async () => {
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id);
  };
  const originalDocument = globalThis.document;
  const originalFetch = globalThis.fetch;
  try {
    globalThis.document = { getElementById: get, createElement: () => new Element() };
    globalThis.fetch = async () => new Response(await readFile(new URL('../docs/evidence.json', import.meta.url)));
    get('rail').value = 'bank'; get('amount').value = '125050';
    await import('../docs/app.js');
    assert.equal(get('results').children.length, 4);
    await get('encrypt').trigger('click');
    assert.match(get('status').textContent, /Encrypted locally/);
    const firstWire = get('wire').textContent;
    assert.ok(!firstWire.includes('public-test-instruction'));
    await get('decrypt').trigger('click');
    assert.equal(JSON.parse(get('wire').textContent).amount, '125050');
    await get('tamper').trigger('click'); await get('decrypt').trigger('click');
    assert.match(get('status').textContent, /AUTHENTICATION FAILED/);
    await get('tamper').trigger('click'); await get('decrypt').trigger('click');
    assert.match(get('status').textContent, /decryption succeeded/);
    get('rail').value = 'crypto'; await get('rail').trigger('change');
    assert.match(get('amount-help').textContent, /USDC/);
    await get('encrypt').trigger('click'); await get('decrypt').trigger('click');
    assert.equal(JSON.parse(get('wire').textContent).network, 'ethereum:1');
    await get('crypto-report').trigger('click');
    assert.match(get('report').textContent, /USDC/);
    get('amount').value = '-1'; await get('encrypt').trigger('click');
    assert.match(get('status').textContent, /positive integer/);
  } finally {
    globalThis.document = originalDocument; globalThis.fetch = originalFetch;
  }
});
