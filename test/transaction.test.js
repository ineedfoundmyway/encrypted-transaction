import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { generateIdentity, SoftwareKeyProvider, MemoryReplayStore, validateTransaction, seal, open, SUITE, fingerprint } from '../src/index.js';

const alice = generateIdentity('alice');
const bob = generateIdentity('bob');
const mallory = generateIdentity('mallory');
const sender = new SoftwareKeyProvider(alice);
const recipient = new SoftwareKeyProvider(bob);
const now = 1_800_000_000_000;
const tx = { id: 'invoice-1', rail: 'bank', sender: 'alice', recipient: 'bob', asset: 'BRL', amount: '10000', network: 'bank', reference: 'order-1' };
const sealOptions = { sender, recipient: { name: 'bob', encryptionKey: bob.encryption.publicKey }, now };
function options(extra = {}) { return { recipient, trustedSender: { name: 'alice', signingKey: alice.signing.publicKey }, now, replayStore: new MemoryReplayStore(), ...extra }; }
const envelope = await seal(tx, sealOptions);
const clone = () => structuredClone(envelope);
function flip(value) { const b = Buffer.from(value, 'base64url'); b[0] ^= 1; return b.toString('base64url'); }
const rejects = (promise, code) => assert.rejects(promise, error => error.code === code);

for (const rail of ['bank', 'crypto']) test(`${rail} exact round trip without floating point`, async () => {
  const payload = rail === 'bank' ? tx : { ...tx, rail, asset: 'USDC', network: 'ethereum:1', amount: '900719925474099312345' };
  const sealed = await seal(payload, sealOptions);
  assert.deepEqual(await open(sealed, options()), payload);
});

test('randomized envelopes and no plaintext in wire payload', async () => {
  const another = await seal(tx, sealOptions);
  assert.notEqual(envelope.kem, another.kem);
  assert.notEqual(envelope.iv, another.iv);
  assert.notEqual(envelope.ciphertext, another.ciphertext);
  assert.ok(!JSON.stringify(envelope).includes('order-1'));
});

for (const field of ['kem', 'salt', 'iv', 'ciphertext', 'tag', 'signature']) test(`reject altered ${field}`, async () => {
  const candidate = clone(); candidate[field] = flip(candidate[field]);
  await rejects(open(candidate, options()), 'INVALID_SIGNATURE');
});

for (const [field, value, code] of [
  ['suite', 'RSA', 'UNSUPPORTED_SUITE'], ['sender', 'mallory', 'UNTRUSTED_SENDER'],
  ['recipient', 'mallory', 'RECIPIENT_MISMATCH'], ['signerKey', 'fake', 'UNTRUSTED_SENDER'],
  ['recipientKey', 'fake', 'RECIPIENT_MISMATCH'], ['messageId', 'different', 'INVALID_SIGNATURE'],
  ['issuedAt', now - 1, 'INVALID_SIGNATURE'], ['expiresAt', now + 50_000, 'INVALID_SIGNATURE'],
]) test(`reject altered header ${field}`, async () => {
  const candidate = clone(); candidate.header[field] = value;
  await rejects(open(candidate, options()), code);
});

test('reject untrusted signing key', async () => {
  await rejects(open(envelope, options({ trustedSender: { name: 'alice', signingKey: mallory.signing.publicKey } })), 'UNTRUSTED_SENDER');
});

test('reject wrong receiver private key after valid signature', async () => {
  await rejects(open(envelope, options({ recipient: { name: 'bob', recipientKey: recipient.recipientKey, decapsulate: new SoftwareKeyProvider(mallory).decapsulate.bind(new SoftwareKeyProvider(mallory)) } })), 'DECRYPTION_FAILED');
});

test('signed ciphertext with invalid GCM tag is rejected', async () => {
  const badSender = { ...sender, name: sender.name, signerKey: sender.signerKey, async sign(data) {
    const fields = JSON.parse(data.toString());
    fields[6] = flip(fields[6]);
    return sign(null, Buffer.from(JSON.stringify(fields)), alice.signing.privateKey);
  } };
  const candidate = await seal(tx, { ...sealOptions, sender: badSender });
  candidate.tag = flip(candidate.tag);
  await rejects(open(candidate, options()), 'DECRYPTION_FAILED');
});

for (const time of [now - 1, now + 60_000, now + 60_001]) test(`reject invalid time ${time}`, async () => {
  await rejects(open(envelope, options({ now: time })), 'INVALID_WINDOW');
});

test('atomic replay consumption accepts exactly one concurrent delivery', async () => {
  const shared = options();
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => open(envelope, shared)));
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.ok(results.filter(r => r.status === 'rejected').every(r => r.reason.code === 'REPLAY_DETECTED'));
});

test('resealing same transaction ID cannot bypass active replay protection', async () => {
  const shared = options(); await open(envelope, shared);
  await rejects(open(await seal(tx, sealOptions), shared), 'REPLAY_DETECTED');
});

test('tampered delivery does not consume replay ID', async () => {
  const shared = options(); const bad = clone(); bad.tag = flip(bad.tag);
  await rejects(open(bad, shared), 'INVALID_SIGNATURE');
  assert.deepEqual(await open(envelope, shared), tx);
});

test('replay store required and failure closed', async () => {
  await rejects(open(envelope, options({ replayStore: null })), 'REPLAY_STORE_REQUIRED');
  await assert.rejects(open(envelope, options({ replayStore: { consume() { throw new Error('database unavailable'); } } })), /database unavailable/);
});

test('bounded replay store refuses eviction of live entries', async () => {
  const store = new MemoryReplayStore({ capacity: 1 });
  assert.equal(await store.consume('a', now + 100, now), true);
  await rejects(store.consume('b', now + 100, now), 'REPLAY_STORE_FULL');
  assert.equal(await store.consume('b', now + 200, now + 100), true);
});

for (const amount of [0, 1.25, '-1', '0', '01', '1.0', '1e6', '9'.repeat(31)]) test(`reject invalid amount ${amount}`, () => {
  assert.throws(() => validateTransaction({ ...tx, amount }));
});

test('reject unknown fields, invalid rails, ambiguous asset and identity', async () => {
  for (const candidate of [{ ...tx, extra: true }, { ...tx, rail: 'wire' }, { ...tx, recipient: 'alice' }, { ...tx, asset: 'USDC' }, { ...tx, network: 'ethereum:1' }, { ...tx, id: '' }]) assert.throws(() => validateTransaction(candidate));
  await rejects(seal({ ...tx, sender: 'mallory' }, sealOptions), 'IDENTITY_MISMATCH');
});

test('reject malformed envelope encodings and excessive lengths', async () => {
  for (const candidate of [null, { ...clone(), extra: true }, { ...clone(), kem: 'A' }, { ...clone(), salt: envelope.salt + '=' }, { ...clone(), ciphertext: 'A'.repeat(30_000) }, { ...clone(), header: { ...envelope.header, extra: true } }]) await rejects(open(candidate, options()), 'INVALID_INPUT');
});

test('reject downgrade key type and excessive TTL', async () => {
  await rejects(seal(tx, { ...sealOptions, ttlMs: 300_001 }), 'INVALID_INPUT');
  await rejects(seal(tx, { ...sealOptions, recipient: { name: 'bob', encryptionKey: generateKeyPairSync('x25519').publicKey } }), 'KEY_TYPE');
  assert.equal(envelope.header.suite, SUITE);
});


test('accept base64url key fingerprints beginning with a hyphen or underscore', async () => {
  function leadingSymbolIdentity(name, purpose) {
    for (let attempt = 0; attempt < 2048; attempt++) {
      const identity = generateIdentity(name);
      if (/^[-_]/.test(fingerprint(identity[purpose].publicKey))) return identity;
    }
    throw new Error('Could not generate a leading-symbol fingerprint');
  }
  const signingIdentity = leadingSymbolIdentity('alice', 'signing');
  const receivingIdentity = leadingSymbolIdentity('bob', 'encryption');
  const candidate = await seal(tx, {
    sender: new SoftwareKeyProvider(signingIdentity),
    recipient: { name: 'bob', encryptionKey: receivingIdentity.encryption.publicKey },
    now,
  });
  assert.match(candidate.header.signerKey, /^[-_]/);
  assert.match(candidate.header.recipientKey, /^[-_]/);
  assert.deepEqual(await open(candidate, {
    recipient: new SoftwareKeyProvider(receivingIdentity),
    trustedSender: { name: 'alice', signingKey: signingIdentity.signing.publicKey },
    replayStore: new MemoryReplayStore(),
    now,
  }), tx);
});
