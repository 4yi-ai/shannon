// AES-256-GCM vault bridge. Secrets arrive only on stdin, never argv/environment.
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
let input = '';
for await (const chunk of process.stdin) input += chunk;
try {
  const { operation, key, data } = JSON.parse(input);
  const bytes = Buffer.from(key, 'base64');
  if (bytes.length !== 32) throw new Error('Invalid key');
  if (operation === 'seal') {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', bytes, iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(data, 'base64')), cipher.final()]);
    process.stdout.write(Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64'));
  } else if (operation === 'open') {
    const blob = Buffer.from(data, 'base64');
    const cipher = createDecipheriv('aes-256-gcm', bytes, blob.subarray(0, 12));
    cipher.setAuthTag(blob.subarray(12, 28));
    process.stdout.write(Buffer.concat([cipher.update(blob.subarray(28)), cipher.final()]).toString('base64'));
  } else throw new Error('Invalid operation');
} catch { process.stderr.write('Credential vault operation failed\n'); process.exitCode = 1; }
