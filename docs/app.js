const $ = id => document.getElementById(id);
const encoder = new TextEncoder();
const aad = encoder.encode('encrypted-transaction/browser-aes-lab/v1');
let current;
let busy = false;
function status(message, error = false) { $('status').textContent = message; $('status').classList.toggle('error', error); }
function encode(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function wire() {
  $('wire').textContent = JSON.stringify({ profile: 'BROWSER-AES256GCM-LAB', nonce: encode(current.iv), aad: new TextDecoder().decode(aad), ciphertextAndTag: encode(current.ciphertext), tampered: current.tampered }, null, 2);
}
async function guarded(action) {
  if (busy) return;
  busy = true;
  try { await action(); }
  catch { status('Operation failed. No plaintext released.', true); }
  finally { busy = false; }
}
$('encrypt').addEventListener('click', () => guarded(async () => {
  const amount = $('amount').value;
  if (!/^[1-9][0-9]{0,29}$/.test(amount)) { status('Enter a positive integer of at most 30 digits.', true); return; }
  const rail = $('rail').value;
  const payload = { id: crypto.randomUUID(), rail, amount, asset: rail === 'bank' ? 'BRL' : 'USDC', network: rail === 'bank' ? 'bank' : 'ethereum:1', reference: 'public-test-instruction' };
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, encoder.encode(JSON.stringify(payload))));
  current = { key, iv, ciphertext, tampered: false };
  wire(); $('decrypt').disabled = false; $('tamper').disabled = false;
  status('Encrypted locally. Try decryption, then flip a bit.');
}));
$('decrypt').addEventListener('click', () => guarded(async () => {
  if (!current) return;
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: current.iv, additionalData: aad, tagLength: 128 }, current.key, current.ciphertext);
    $('wire').textContent = JSON.stringify(JSON.parse(new TextDecoder().decode(plaintext)), null, 2);
    new Uint8Array(plaintext).fill(0);
    status('Authenticated decryption succeeded. No transaction submitted.');
  } catch {
    wire(); status('AUTHENTICATION FAILED — modified ciphertext rejected.', true);
  }
}));
$('tamper').addEventListener('click', () => {
  if (busy || !current) return;
  current.ciphertext[0] ^= 1; current.tampered = !current.tampered; wire();
  status(current.tampered ? 'One ciphertext bit changed. Decrypt to check authentication.' : 'Original ciphertext restored.');
});
$('rail').addEventListener('change', () => {
  $('amount-help').textContent = $('rail').value === 'bank' ? 'BRL cents: 125050 = BRL 1,250.50. Use test values only.' : 'USDC base units (6 decimals): 25000000 = 25 USDC. Test intent only.';
});
let reports = [];
function displayReport(rail) {
  const report = reports.find(r => r.rail === rail);
  if (!report) return;
  $('runtime').textContent = `Executed ${report.generatedAt} · Node ${report.runtime} · ${report.durationMs} ms for sealing and scenario checks (single run, not a benchmark).`;
  $('results').replaceChildren(...report.results.map(result => {
    const card = document.createElement('div'); card.className = 'result';
    const label = document.createElement('span'); label.textContent = result.scenario;
    const value = document.createElement('strong'); value.textContent = result.result;
    card.append(label, value); return card;
  }));
  $('report').textContent = JSON.stringify({ recoveredTestPayload: report.recovered, envelope: report.envelope }, null, 2);
  for (const choice of ['bank', 'crypto']) {
    $(`${choice}-report`).setAttribute('aria-pressed', String(choice === rail));
    $(`${choice}-report`).classList.toggle('secondary', choice !== rail);
  }
}
for (const rail of ['bank', 'crypto']) $(`${rail}-report`).addEventListener('click', () => displayReport(rail));
try {
  const response = await fetch('./evidence.json');
  if (!response.ok) throw new Error('Evidence unavailable');
  reports = (await response.json()).reports; displayReport('bank');
} catch { $('runtime').textContent = 'Execution evidence unavailable. Run npm run build before serving the docs directory.'; }
