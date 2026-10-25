# Validation record

Validated locally on Node.js v24.22.1.

- `npm test`: 41 passed, zero failures.
- `npm run demo`: bank and crypto examples executed with native ML-KEM / ML-DSA.
- `npm run build`: fresh public execution evidence generated without private-key export.
- `npm run check`: JavaScript syntax and private-key marker checks passed.
- Core protocol and SQLite source: 100% reported line, branch and function coverage.
- Browser module: exercised with actual Web Crypto and a minimal DOM test adapter; successful decryption, tamper rejection, input validation and evidence selection passed.

A graphical browser was unavailable locally and its binary download failed. The cloud browser could not reach the local preview, so responsive layout and visual appearance have not been verified in a rendered browser. Tests are not an independent cryptographic audit or interoperability certification.

# Publication tracking

The initial integration-based publication attempt was blocked by GitHub with HTTP 403. Publication was subsequently prepared through the authenticated browser session. Consult the repository commit history, pull request and Actions runs for current publication and deployment status.

The requested coauthor identity is `brunnojob <contato@brunnodev.store>`. No independent human review is asserted.
