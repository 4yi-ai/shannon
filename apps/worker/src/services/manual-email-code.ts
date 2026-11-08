// Copyright (C) 2026 Keygraph, Inc. AGPL-3.0-or-later.
import { createDecipheriv, randomUUID } from 'node:crypto';
import { readFile, writeFile, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { defineTool } from '@earendil-works/pi-coding-agent';
import { Type } from 'typebox';

type Reason = 'initial' | 'incorrect' | 'after_resend';
interface Session { attempt: number; deadline: number; status: string; resendAfter?: number }
export class EmailResendRequested extends Error {}

/** Bounded rounds within the same browser session; never retries username/password. */
export async function waitForEmailCode(directory: string, keyPath: string, signal?: AbortSignal,
  timeoutMs = 300_000, reason: Reason = 'initial', totalTimeoutMs = timeoutMs): Promise<string> {
  const requestPath = path.join(directory, 'otp-request.json');
  const responsePath = path.join(directory, 'otp-response.enc');
  const sessionPath = path.join(directory, 'otp-session.json');
  const lockPath = path.join(directory, 'otp-lock');
  await writeFile(lockPath, '', {mode: 0o600, flag: 'wx'});
  let session: Session | undefined;
  let published = false;
  const status = async (value: string) => {
    if (session) {
      session.status = value;
      await writeFile(sessionPath, JSON.stringify(session), {mode: 0o600});
      await writeFile(path.join(directory, 'otp-status.json'), JSON.stringify({status: value}), {mode: 0o600});
    }
  };
  try {
    try { session = JSON.parse(await readFile(sessionPath, 'utf8')) as Session; }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    if (!session) {
      if (reason !== 'initial') throw new Error('No initial email challenge');
      session = {attempt: 0, deadline: Date.now() + totalTimeoutMs, status: 'new'};
    } else if (!((session.status === 'received' && reason === 'incorrect') ||
                 (session.status === 'resend_requested' && reason === 'after_resend'))) {
      throw new Error('Email verification round cannot be repeated');
    }
    if (session.attempt >= 3) throw new Error('Email verification attempt limit reached');
    if (Date.now() >= session.deadline) throw new Error('Email verification timed out');
    session.attempt += 1;
    if (reason !== 'incorrect') session.resendAfter = Date.now() + 60_000;
    await status('waiting');
    const id = randomUUID().replaceAll('-', '');
    const now = Date.now();
    const request = {id, expires_at: Math.min(now + timeoutMs, session.deadline) / 1000,
      deadline_at: session.deadline / 1000, resend_after: (session.resendAfter ?? now + 60_000) / 1000,
      attempt: session.attempt, max_attempts: 3, reason};
    await writeFile(`${requestPath}.tmp`, JSON.stringify(request), {mode: 0o600});
    await rename(`${requestPath}.tmp`, requestPath);
    published = true;
    while (Date.now() < session.deadline && (session.attempt < 3 || Date.now() < request.expires_at * 1000)) {
      signal?.throwIfAborted();
      let encrypted: Buffer;
      try { encrypted = await readFile(responsePath); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('Email verification storage unavailable');
        await delay(200, undefined, signal ? {signal} : {});
        continue;
      }
      const decipher = createDecipheriv('aes-256-gcm', await readFile(keyPath), encrypted.subarray(0, 12));
      decipher.setAuthTag(encrypted.subarray(12, 28));
      const payload = JSON.parse(Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]).toString('utf8')) as {request_id?: string; code?: string; action?: string};
      if (payload.request_id !== id) throw new Error('Invalid email verification response');
      if (payload.action === 'resend') {
        await status('resend_requested');
        throw new EmailResendRequested('Operator requested another email');
      }
      if (typeof payload.code !== 'string' || !/^[A-Za-z0-9]{4,12}$/.test(payload.code)) throw new Error('Invalid email verification response');
      await status('received');
      return payload.code;
    }
    throw new Error('Email verification timed out');
  } catch (error) {
    if (!(error instanceof EmailResendRequested)) {
      await status(signal?.aborted ? 'cancelled' : ((session && Date.now() >= session.deadline) || (error instanceof Error && error.message === 'Email verification timed out')) ? 'expired' : 'failed');
    }
    throw error;
  } finally {
    const files = published ? [requestPath, responsePath, `${requestPath}.tmp`, lockPath] : [lockPath];
    await Promise.all(files.map(file => rm(file, {force: true})));
  }
}

export function manualEmailCodeTool(directory: string, keyPath: string) {
  return defineTool({
    name: 'request_email_code', label: 'Wait for email verification code',
    description: 'Wait for the operator in the same login session. Use initial after the site sends the first email; incorrect only after the site explicitly rejects the submitted email code; after_resend only after the operator requested resending AND you clicked the site resend button once. At most three rounds, eight minutes total. Never repeat username/password login. Never print codes or include them in reports.',
    parameters: Type.Object({reason: Type.Optional(Type.Union([Type.Literal('initial'), Type.Literal('incorrect'), Type.Literal('after_resend')]))}),
    execute: async (_id, params, signal) => {
      try {
        const code = await waitForEmailCode(directory, keyPath, signal, 300_000, params.reason ?? 'initial', 480_000);
        return {content: [{type: 'text' as const, text: `Use this one-time email code in the current login form only: ${code}. Do not echo it. If the site explicitly rejects this code while keeping its code form, call request_email_code with reason=incorrect to let the operator correct it. Never resubmit username/password.`}], details: {received: true, resendRequested: false}};
      } catch (error) {
        if (error instanceof EmailResendRequested) {
          return {content: [{type: 'text' as const, text: 'The operator requests a new email. In this same browser session click the target website resend-code control exactly once, respecting any site cooldown. Only after the site confirms sending, call request_email_code with reason=after_resend. If the control is unavailable or the site refuses, stop and submit login_success=false, failure_point=out_of_band. Do not restart login.'}], details: {received: false, resendRequested: true}};
        }
        return {isError: true, content: [{type: 'text' as const, text: 'Email verification time/attempt limit reached, cancelled, or storage failed. Stop and submit login_success=false, failure_point=out_of_band. Do not retry login.'}], details: {received: false, resendRequested: false}};
      }
    },
  });
}
