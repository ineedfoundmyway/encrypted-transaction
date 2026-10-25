# Security model

## Intended use

This repository studies confidential, authenticated transaction instructions between parties with pre-established trust. It does not execute payments, provide custody or connect to a bank. Deploy only the static demonstration. Independent protocol review, implementation audit and operational controls are required before considering a financial integration.

## Attacker model

An attacker may read, modify, substitute, delay or replay an envelope. The receiver requires a pinned sender public key and its own private-key provider. A sender key supplied inside an untrusted message is never used to establish trust. Compromised endpoints, authorized malicious senders and stolen private keys are outside the protection offered by encryption.

The signature binds the full envelope. Header fields are also GCM AAD. The receiver enforces a maximum five-minute lifetime, rejects future issuance without clock-skew allowance and verifies the signature before decapsulation. Both clocks must be synchronized. Values are returned only after successful GCM authentication and payload validation.

## Replay and settlement

`MemoryReplayStore` is bounded, process-local and expires records with their envelope. Its check-and-insert executes without yielding. At capacity it fails closed rather than evicting live records. It is a demonstration store: restarts and multiple workers require persistent coordination, and a newly issued envelope can reuse an ID after its old record expires.

`SQLiteReplayStore` uses a unique primary key and atomic INSERT OR IGNORE. Records survive expiry and restart. Two connections to the same database cannot accept the same replay key. A busy/unavailable database throws; the caller must reject acceptance. There is no automatic pruning. Retention, protected file access, backup and recovery require operator policy.

Replay keys hash sender, recipient and transaction ID. They intentionally exclude key fingerprints, so key rotation cannot bypass retained IDs. Scope is one database; copied databases and different replicas do not coordinate.

Consuming an ID is separate from executing a payment. A crash between acceptance and settlement can lose an instruction. A production service needs a durable inbox/outbox and business ledger in the same transaction, recovery semantics and authorization checks. This library makes no exactly-once payment claim.

## Key custody

`SoftwareKeyProvider` keeps Node KeyObjects in process memory. It does not export private keys but does not provide hardware isolation. Generated identities expose private KeyObjects to their caller for this local research API. Best-effort zeroing covers shared-secret buffers, derived AES keys and decrypted byte buffers; JavaScript strings, runtime copies, returned objects and OpenSSL memory are not guaranteed to be erased.

An external provider must implement `name`, `signerKey`, `recipientKey`, async `sign(bytes)` and async `decapsulate(kemCiphertext)`. It must bind fingerprints to the intended keys and enforce operation policy. An HSM integration must verify the device supports the exact ML-DSA and ML-KEM mechanisms. This interface returns the KEM shared secret to the host for AES derivation; it does not keep all operations inside hardware. No HSM driver, PKCS#11 adapter, attestation or FIPS 140-3 validation is included.

Recipient public keys must be authenticated before sealing. Long-term receiver-key compromise permits decryption of retained envelopes; fresh encapsulations do not create forward secrecy. Rotation, revocation, directory integrity, key recovery and backup are external responsibilities.

## Data and resource limits

Amounts are positive decimal integer strings of at most 30 digits. Currency precision, account ownership, contract addresses, chain identity, fees and limits are settlement policy. The crypto example uses an asset symbol for study, not a unique token identifier.

Public headers expose sender, recipient, key fingerprints, message ID and timestamps. Encryption does not hide traffic volume or message length. Individual ciphertexts are bounded to 16 KiB after decoding. An API wrapper must enforce request byte limits before JSON parsing, authentication, authorization, rate limits, TLS and worker isolation. Native synchronous crypto operations can block an event loop.

## Disclosure

Report vulnerabilities through the repository's private security reporting feature if enabled. Otherwise contact the maintainer to establish a private disclosure channel before sending sensitive details. Never publish live credentials or exploitable production data in an issue.
