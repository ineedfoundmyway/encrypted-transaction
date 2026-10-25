# ETX version 1 wire format

Suite: `ETX1-MLKEM768-MLDSA65-HKDFSHA256-AES256GCM`. Unknown suites are rejected; no negotiation or fallback is performed.

The outer object contains exactly `header`, `kem`, `salt`, `iv`, `ciphertext`, `tag` and `signature`. Byte strings are canonical unpadded base64url. Headers contain exactly the fields below.

| Field | Meaning |
| --- | --- |
| suite | Exact protocol suite identifier |
| sender / recipient | Caller-provisioned identity names |
| signerKey / recipientKey | SHA-256 of the corresponding SPKI DER public key, base64url |
| messageId | Fresh random UUID produced by the sender |
| issuedAt / expiresAt | Integer Unix milliseconds, lifetime at most 300000 ms |

Header encoding is UTF-8 JSON of the ordered array `[suite,sender,recipient,signerKey,recipientKey,messageId,issuedAt,expiresAt]`. JSON object member order therefore does not change verification. Token fields permit ASCII alphanumeric plus `:._/-`, begin with alphanumeric and are at most 128 characters. Identity names and IDs are case-sensitive.

The domain is the UTF-8 byte string `encrypted-transaction/v1` followed by one NUL byte. ML-KEM-768 encapsulation produces a fresh shared secret and 1088-byte KEM ciphertext. HKDF-SHA-256 uses that secret, a random 32-byte salt, and `domain || encodedHeader` as info, producing 32 bytes. AES-256-GCM uses a random 12-byte IV, the encoded header as AAD and a 16-byte tag.

The signed transcript is UTF-8 JSON of the ordered array `[base64url(domain),base64url(encodedHeader),kem,salt,iv,ciphertext,tag]`. ML-DSA-65 signs those exact bytes with Node's `sign(null, ...)`; signatures are 3309 bytes. This explicit array encoding is local to ETX and is not a claim of RFC 8785 canonical JSON conformance.

The encrypted payload has exactly `id`, `rail`, `sender`, `recipient`, `asset`, `amount`, `network` and `reference`. Sender and recipient must agree with the header. The sender constructs payload fields in that order. Receivers validate the parsed object independently of property order.

Receiver order: snapshot the input; validate schema, lengths, trust and time; verify ML-DSA; decapsulate; derive key; authenticate/decrypt; validate payload and identity binding; atomically consume SHA-256 of JSON `[sender,recipient,transactionId]`; return the instruction. Failures never release unauthenticated plaintext. Provider and store failures propagate as rejection.

No private keys are transported in the envelope. No external interoperability, formal composition proof, FIPS validation or resistance to compromised application endpoints is asserted.
