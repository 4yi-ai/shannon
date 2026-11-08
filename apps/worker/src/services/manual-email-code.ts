// Copyright (C) 2026 Keygraph, Inc. AGPL-3.0-or-later.
import { createDecipheriv, randomUUID } from 'node:crypto';
import { readFile, writeFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { defineTool } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';

/** Only this browser-login activity can request an operator's email code. */
export async function waitForEmailCode(directory: string, keyPath: string, signal?: AbortSignal, timeoutMs = 300_000): Promise<string> {
  const requestPath = path.join(directory, 'otp-request.json');
  const responsePath = path.join(directory, 'otp-response.enc');
  const id = randomUUID().replaceAll('-', '');
  const expiresAt = Date.now() + timeoutMs;
  // One attempt per task. A Temporal activity retry cannot trigger another email/login loop.
  await writeFile(path.join(directory, 'otp-used'), 'used', { mode: 0o600, flag: 'wx' });
  try {
    await writeFile(`${requestPath}.tmp`, JSON.stringify({ id, expires_at: expiresAt / 1000 }), { mode: 0o600 });
    await rename(`${requestPath}.tmp`, requestPath);
    while (Date.now() < expiresAt) {
      signal?.throwIfAborted();
      let encrypted: Buffer;
      try { encrypted = await readFile(responsePath); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('Email verification storage unavailable');
        await delay(200, undefined, signal ? { signal } : {});
        continue;
      }
      const key = await readFile(keyPath);
      const decipher = createDecipheriv('aes-256-gcm', key, encrypted.subarray(0, 12));
      decipher.setAuthTag(encrypted.subarray(12, 28));
      const payload = JSON.parse(Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]).toString('utf8')) as {request_id?: string; code?: string};
      if (payload.request_id !== id || typeof payload.code !== 'string' || !/^[A-Za-z0-9]{4,12}$/.test(payload.code)) {
        throw new Error('Invalid email verification response');
      }
      await writeFile(path.join(directory, 'otp-status.json'), JSON.stringify({status: 'received'}), {mode: 0o600});
      return payload.code;
    }
    throw new Error('Email verification timed out');
  } catch (error) {
    const status = signal?.aborted ? 'cancelled' : Date.now() >= expiresAt ? 'expired' : 'failed';
    await writeFile(path.join(directory, 'otp-status.json'), JSON.stringify({status}), {mode: 0o600});
    throw error;
  } finally {
    await Promise.all([requestPath, responsePath, `${requestPath}.tmp`].map(file => rm(file, { force: true })));
  }
}

export function manualEmailCodeTool(directory: string, keyPath: string) {
  return defineTool({
    name: 'request_email_code',
    label: 'Wait for email verification code',
    description: 'Call only after the target website has sent its login email and is showing the verification code field. Waits up to five minutes for the operator. Call once only. Never print the returned code or include it in reports.',
    parameters: Type.Object({}),
    execute: async (_id, _params, signal) => {
      try {
        const code = await waitForEmailCode(directory, keyPath, signal);
        return { content: [{type: 'text' as const, text: `Use this one-time email code in the current login form only: ${code}. Do not echo it.`}], details: { received: true } };
      } catch {
        return { isError: true, content: [{type: 'text' as const, text: 'Email verification expired, was cancelled, or could not be read. Stop and submit login_success=false, failure_point=out_of_band. Do not retry login or request another code.'}], details: { received: false } };
      }
    },
  });
}
