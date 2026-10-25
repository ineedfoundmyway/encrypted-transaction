import { readdir, readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
async function check(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory()) await check(path);
    else if (entry.name.endsWith('.js')) execFileSync(process.execPath, ['--check', path]);
    if (entry.isFile() && /\.(js|json|md|html|yml|css)$/.test(path)) {
      const content = await readFile(path, 'utf8');
      if (/-----BEGIN (?:PRIVATE|ENCRYPTED PRIVATE) KEY-----/.test(content)) throw new Error(`Private key found in ${path}`);
    }
  }
}
for (const path of ['src', 'scripts', 'test', 'docs', '.github']) await check(path);
console.log('Syntax and private-key checks passed.');
