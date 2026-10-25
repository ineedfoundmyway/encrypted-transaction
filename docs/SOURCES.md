# Sources and implementation decisions

The implementation is original code built with Node.js native cryptographic primitives. Articles inform the threat model; normative specifications determine primitive roles and parameters. No article code or text is copied.

## Primary technical references

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final): post-quantum key establishment; it does not itself authenticate the sender or execute a payment.
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final): post-quantum signatures. Used separately from the KEM.
- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final): authenticated symmetric encryption with associated data.
- [RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869): extraction and context-bound key derivation.
- [Node.js 24 crypto API](https://nodejs.org/docs/latest-v24.x/api/crypto.html): native KEM, signing, HKDF and GCM interfaces. Runtime API stability is separate from algorithm standardization.
- [NIST FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final): cryptographic module security requirements. Using specified algorithms does not confer module validation or hardware isolation.

## User-supplied reading

[Cryptography and Security in Banking, Joshua Reynolds, 2019](https://medium.com/@joshuareynolds/cryptography-and-security-in-banking-2cce7691e70f) was reviewed as historical banking context. It is not the implementation specification. This project uses authenticated AES-GCM rather than reproducing legacy DES/3DES discussions.

[Post-Quantum Cryptography for Secure Banking Transactions, Timothy Olatunji Ogundola, 2025](https://www.researchgate.net/publication/393485157_Post-Quantum_Cryptography_for_Secure_Banking_Transactions) motivates migration planning and crypto-agility. Its suggested hybrid deployments are background; ETX v1 deliberately implements one fixed PQC-only profile, not a hybrid combiner. Standard names and publication chronology are checked against NIST rather than inherited from the article.

The following supplied Brave Ask conversations could not be retrieved during implementation. They are preserved for traceability, not cited as verified evidence:

- [PQC versus RSA and ECC](https://search.brave.com/ask?q=How%20do%20PQC%20algorithms%20differ%20from%20RSA%20and%20ECC%3F&source=llmFollowup&conversation=09b9853b3e15cc0575b700d159d08c6be064&query_type=answer_with_ai_follow_up)
- [Quantum attacks on banks](https://search.brave.com/ask?q=What%20are%20the%20risks%20of%20quantum%20attacks%20on%20banks%3F&source=llmFollowup&conversation=09b9853b3e15cc0575b700d159d08c6be064&query_type=answer_with_ai_follow_up)
- [HSMs and crypto security](https://search.brave.com/ask?q=How%20do%20HSMs%20enhance%20crypto%20security%3F&source=llmFollowup&conversation=09b9853b3e15cc0575b700d159d08c6be064&query_type=answer_with_ai_follow_up)

## Decision boundaries

RSA and ECC address different mathematical problems from ML-KEM and ML-DSA and are exposed to sufficiently capable quantum attacks. The selected PQC algorithms target that class of threat, but protocol construction, implementation defects and key theft remain relevant. This project makes no universal quantum-proof claim.

HSMs can strengthen custody and enforce operation policy, subject to device capabilities and configuration. The included software provider is explicitly not an HSM. Blockchain-native signatures and bank authorization remain outside this envelope protocol.
