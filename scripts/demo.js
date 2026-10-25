import { generateIdentity, SoftwareKeyProvider, MemoryReplayStore, seal, open } from '../src/index.js';

export async function runDemo(rail = 'bank') {
  const alice = generateIdentity('treasury');
  const bob = generateIdentity('settlement');
  const sender = new SoftwareKeyProvider(alice);
  const recipient = new SoftwareKeyProvider(bob);
  const trustedSender = { name: alice.name, signingKey: alice.signing.publicKey };
  const tx = {
    id: `demo-${rail}-001`, rail, sender: alice.name, recipient: bob.name,
    asset: rail === 'bank' ? 'BRL' : 'USDC', amount: rail === 'bank' ? '125050' : '25000000',
    network: rail === 'bank' ? 'bank' : 'ethereum:1', reference: 'invoice-2026-1042',
  };
  const now = Date.now();
  const start = performance.now();
  const envelope = await seal(tx, { sender, recipient: { name: bob.name, encryptionKey: bob.encryption.publicKey }, now });
  const options = { recipient, trustedSender, replayStore: new MemoryReplayStore(), now };
  const recovered = await open(envelope, options);
  const results = [{ scenario: 'Authenticated envelope', result: 'ACCEPTED' }];
  for (const [scenario, candidate, settings] of [
    ['Replay same transaction', envelope, options],
    ['Tamper ciphertext', { ...envelope, ciphertext: `${envelope.ciphertext[0] === 'A' ? 'B' : 'A'}${envelope.ciphertext.slice(1)}` }, { ...options, replayStore: new MemoryReplayStore() }],
    ['Expired envelope', envelope, { ...options, now: now + 60_000 }],
  ]) {
    try { await open(candidate, settings); throw new Error('Scenario unexpectedly accepted'); }
    catch (error) {
      if (!error.code) throw error;
      results.push({ scenario, result: error.code });
    }
  }
  return { rail, generatedAt: new Date(now).toISOString(), runtime: process.version, durationMs: Number((performance.now() - start).toFixed(2)), recovered, envelope, results };
}

if (process.argv[1]?.endsWith('/demo.js')) {
  for (const rail of ['bank', 'crypto']) console.log(JSON.stringify(await runDemo(rail), null, 2));
}
