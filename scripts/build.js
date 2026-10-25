import { writeFile } from 'node:fs/promises';
import { runDemo } from './demo.js';
const reports = await Promise.all(['bank', 'crypto'].map(runDemo));
await writeFile(new URL('../docs/evidence.json', import.meta.url), JSON.stringify({ reports }, null, 2) + '\n');
console.log('Generated public PQC execution evidence for bank and crypto payloads. No private keys exported.');
