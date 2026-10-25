import {
  createCipheriv, createDecipheriv, createHash, decapsulate, encapsulate,
  generateKeyPairSync, hkdfSync, randomBytes, randomUUID, sign, verify,
} from 'node:crypto';

export const SUITE = 'ETX1-MLKEM768-MLDSA65-HKDFSHA256-AES256GCM';
const DOMAIN = Buffer.from('encrypted-transaction/v1\0');
const MAX_BYTES = 16_384;
const MAX_TTL = 300_000;
const token = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;

export class TransactionError extends Error {
  constructor(code) {
    super(code);
    this.name = 'TransactionError';
    this.code = code;
  }
}

function requireValue(condition, code = 'INVALID_INPUT') {
  if (!condition) throw new TransactionError(code);
}

function shape(value, names) {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value));
  const keys = Object.keys(value).sort();
  requireValue(keys.join(',') === [...names].sort().join(','));
}

function id(value) {
  requireValue(typeof value === 'string' && token.test(value));
}

function bytes(value, length, maximum = length) {
  requireValue(typeof value === 'string' && value.length <= Math.ceil(maximum * 4 / 3));
  requireValue(/^[A-Za-z0-9_-]+$/.test(value));
  const decoded = Buffer.from(value, 'base64url');
  requireValue(decoded.toString('base64url') === value);
  requireValue(decoded.length >= length && decoded.length <= maximum);
  return decoded;
}

export function validateTransaction(tx) {
  shape(tx, ['id', 'rail', 'sender', 'recipient', 'asset', 'amount', 'network', 'reference']);
  for (const field of ['id', 'sender', 'recipient', 'asset', 'network', 'reference']) id(tx[field]);
  requireValue(tx.rail === 'bank' || tx.rail === 'crypto');
  requireValue(typeof tx.amount === 'string' && /^[1-9][0-9]{0,29}$/.test(tx.amount));
  requireValue(tx.sender !== tx.recipient);
  requireValue(tx.rail === 'bank' ? /^[A-Z]{3}$/.test(tx.asset) && tx.network === 'bank' : tx.network !== 'bank');
  return Object.fromEntries(['id', 'rail', 'sender', 'recipient', 'asset', 'amount', 'network', 'reference'].map(k => [k, tx[k]]));
}

export function generateIdentity(name) {
  id(name);
  return Object.freeze({ name, encryption: generateKeyPairSync('ml-kem-768'), signing: generateKeyPairSync('ml-dsa-65') });
}

export function fingerprint(publicKey) {
  return createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url');
}

export class SoftwareKeyProvider {
  #identity;
  constructor(identity) {
    this.#identity = identity;
    this.name = identity.name;
    this.signerKey = fingerprint(identity.signing.publicKey);
    this.recipientKey = fingerprint(identity.encryption.publicKey);
  }
  async sign(data) { return sign(null, data, this.#identity.signing.privateKey); }
  async decapsulate(ciphertext) { return decapsulate(this.#identity.encryption.privateKey, ciphertext); }
}

export class MemoryReplayStore {
  #entries = new Map();
  constructor({ capacity = 10_000 } = {}) {
    requireValue(Number.isSafeInteger(capacity) && capacity > 0);
    this.capacity = capacity;
  }
  async consume(key, expiresAt, now) {
    for (const [entry, expiry] of this.#entries) if (expiry <= now) this.#entries.delete(entry);
    if (this.#entries.has(key)) return false;
    requireValue(this.#entries.size < this.capacity, 'REPLAY_STORE_FULL');
    this.#entries.set(key, expiresAt);
    return true;
  }
}

function headerBytes(h) {
  return Buffer.from(JSON.stringify([
    h.suite, h.sender, h.recipient, h.signerKey, h.recipientKey,
    h.messageId, h.issuedAt, h.expiresAt,
  ]));
}

function transcript(h, kem, salt, iv, ciphertext, tag) {
  return Buffer.from(JSON.stringify([
    DOMAIN.toString('base64url'), headerBytes(h).toString('base64url'),
    kem, salt, iv, ciphertext, tag,
  ]));
}

function derive(secret, salt, h) {
  return Buffer.from(hkdfSync('sha256', secret, salt, Buffer.concat([DOMAIN, headerBytes(h)]), 32));
}

function clock(now) { requireValue(Number.isSafeInteger(now) && now >= 0); }

export async function seal(tx, { sender, recipient, now = Date.now(), ttlMs = 60_000 }) {
  clock(now);
  requireValue(Number.isSafeInteger(ttlMs) && ttlMs > 0 && ttlMs <= MAX_TTL);
  const payload = validateTransaction(tx);
  requireValue(payload.sender === sender.name && payload.recipient === recipient.name, 'IDENTITY_MISMATCH');
  requireValue(recipient.encryptionKey.asymmetricKeyType === 'ml-kem-768', 'KEY_TYPE');
  requireValue(Number.isSafeInteger(now + ttlMs));
  const h = {
    suite: SUITE, sender: sender.name, recipient: recipient.name,
    signerKey: sender.signerKey, recipientKey: fingerprint(recipient.encryptionKey),
    messageId: randomUUID(), issuedAt: now, expiresAt: now + ttlMs,
  };
  const { sharedKey, ciphertext: kemBytes } = encapsulate(recipient.encryptionKey);
  const saltBytes = randomBytes(32);
  const ivBytes = randomBytes(12);
  let key;
  try {
    key = derive(sharedKey, saltBytes, h);
    const cipher = createCipheriv('aes-256-gcm', key, ivBytes, { authTagLength: 16 });
    cipher.setAAD(headerBytes(h));
    const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(payload))), cipher.final()]).toString('base64url');
    const kem = kemBytes.toString('base64url');
    const salt = saltBytes.toString('base64url');
    const iv = ivBytes.toString('base64url');
    const tag = cipher.getAuthTag().toString('base64url');
    const signature = (await sender.sign(transcript(h, kem, salt, iv, ciphertext, tag))).toString('base64url');
    bytes(signature, 3309);
    return { header: h, kem, salt, iv, ciphertext, tag, signature };
  } finally {
    sharedKey.fill(0);
    key?.fill(0);
  }
}

export async function open(envelope, { recipient, trustedSender, replayStore, now = Date.now() }) {
  clock(now);
  envelope = structuredClone(envelope);
  shape(envelope, ['header', 'kem', 'salt', 'iv', 'ciphertext', 'tag', 'signature']);
  const h = envelope.header;
  shape(h, ['suite', 'sender', 'recipient', 'signerKey', 'recipientKey', 'messageId', 'issuedAt', 'expiresAt']);
  requireValue(h.suite === SUITE, 'UNSUPPORTED_SUITE');
  for (const field of ['sender', 'recipient', 'messageId', 'signerKey', 'recipientKey']) id(h[field]);
  requireValue(h.recipient === recipient.name && h.recipientKey === recipient.recipientKey, 'RECIPIENT_MISMATCH');
  requireValue(h.sender === trustedSender.name && h.signerKey === fingerprint(trustedSender.signingKey), 'UNTRUSTED_SENDER');
  requireValue(trustedSender.signingKey.asymmetricKeyType === 'ml-dsa-65', 'KEY_TYPE');
  clock(h.issuedAt);
  clock(h.expiresAt);
  requireValue(h.issuedAt <= now && h.expiresAt > now && h.expiresAt > h.issuedAt && h.expiresAt - h.issuedAt <= MAX_TTL, 'INVALID_WINDOW');
  const kem = bytes(envelope.kem, 1088);
  const salt = bytes(envelope.salt, 32);
  const iv = bytes(envelope.iv, 12);
  const ciphertext = bytes(envelope.ciphertext, 1, MAX_BYTES);
  const tag = bytes(envelope.tag, 16);
  const signature = bytes(envelope.signature, 3309);
  requireValue(verify(null, transcript(h, envelope.kem, envelope.salt, envelope.iv, envelope.ciphertext, envelope.tag), trustedSender.signingKey, signature), 'INVALID_SIGNATURE');
  let secret;
  let key;
  let plaintext;
  try {
    secret = await recipient.decapsulate(kem);
    key = derive(secret, salt, h);
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    decipher.setAAD(headerBytes(h));
    decipher.setAuthTag(tag);
    const pending = decipher.update(ciphertext);
    try { plaintext = Buffer.concat([pending, decipher.final()]); }
    finally { pending.fill(0); }
  } catch {
    throw new TransactionError('DECRYPTION_FAILED');
  } finally {
    secret?.fill(0);
    key?.fill(0);
  }
  let tx;
  try { tx = validateTransaction(JSON.parse(plaintext.toString('utf8'))); }
  finally { plaintext.fill(0); }
  requireValue(tx.sender === h.sender && tx.recipient === h.recipient, 'IDENTITY_MISMATCH');
  requireValue(replayStore && typeof replayStore.consume === 'function', 'REPLAY_STORE_REQUIRED');
  const replayKey = createHash('sha256').update(JSON.stringify([h.sender, h.recipient, tx.id])).digest('hex');
  requireValue(await replayStore.consume(replayKey, h.expiresAt, now), 'REPLAY_DETECTED');
  return tx;
}
