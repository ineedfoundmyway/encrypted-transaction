# Validation record

Validated locally on Node.js v24.22.1.

- `npm test`: 42 passed, zero failures.
- `npm run demo`: bank and crypto examples executed with native ML-KEM / ML-DSA.
- `npm run build`: fresh public execution evidence generated without private-key export.
- `npm run check`: JavaScript syntax and private-key marker checks passed.
- Core protocol and SQLite source: 100% reported line, branch and function coverage.
- Browser module: exercised with actual Web Crypto and a minimal DOM test adapter; successful decryption, tamper rejection, input validation and evidence selection passed.

After deployment, the live Pages site was checked in a graphical browser: encryption, authenticated decryption and rejection of modified ciphertext succeeded. Desktop layout was visually inspected. Mobile rendering has not been separately verified. Tests are not an independent cryptographic audit or interoperability certification.

# Publication tracking

The code was published through the brunnojob browser session and merged in PR #1. The Pages workflow completed successfully. A subsequent verification exposed rejection of valid leading-symbol fingerprints; the validation was corrected and a dedicated round-trip regression test was added. Consult Actions for the latest verification and deployment status.

The requested coauthor identity is `brunnojob <contato@brunnodev.store>`. No independent human review is asserted.
