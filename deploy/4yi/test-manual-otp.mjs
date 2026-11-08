// Local IPC fixtures only: no model, mailbox, website or credentials involved.
import assert from 'node:assert/strict';
import { randomBytes, createCipheriv } from 'node:crypto';
import { mkdtemp, readFile, writeFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { waitForEmailCode, EmailResendRequested } from '../../apps/worker/dist/services/manual-email-code.js';

async function fixture(test) {
  const directory = await mkdtemp(path.join(tmpdir(),'shannon-otp-'));
  const keyPath = path.join(directory,'key'), key = randomBytes(32);
  await writeFile(keyPath,key,{mode:0o600});
  try { await test(directory,keyPath,key); } finally { await rm(directory,{recursive:true,force:true}); }
}
async function pending(directory) {
  for(let i=0;i<100;i++){
    try{return JSON.parse(await readFile(path.join(directory,'otp-request.json'),'utf8'));}catch{}
    await delay(20);
  }
  throw new Error('Challenge not published');
}
function seal(key,value) {
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);
  const data=Buffer.concat([cipher.update(JSON.stringify(value)),cipher.final()]);
  return Buffer.concat([iv,cipher.getAuthTag(),data]);
}
await fixture(async(directory,keyPath,key)=>{
  const waiting=waitForEmailCode(directory,keyPath,undefined,3000);
  const request=await pending(directory);
  assert.match(request.id,/^[a-f0-9]{32}$/);assert(request.expires_at*1000>Date.now());
  const encrypted=seal(key,{request_id:request.id,code:'246810'});
  assert(!encrypted.includes(Buffer.from('246810')));
  await writeFile(path.join(directory,'otp-response.enc'),encrypted);
  assert.equal(await waiting,'246810');
  await assert.rejects(access(path.join(directory,'otp-request.json')));
  await assert.rejects(access(path.join(directory,'otp-response.enc')));
  await assert.rejects(waitForEmailCode(directory,keyPath,undefined,10));
});
await fixture(async(directory,keyPath)=>{
  await assert.rejects(waitForEmailCode(directory,keyPath,undefined,20),/timed out/);
  assert.equal(JSON.parse(await readFile(path.join(directory,'otp-status.json'))).status,'expired');
  await assert.rejects(access(path.join(directory,'otp-request.json')));
});
await fixture(async(directory,keyPath)=>{
  const controller=new AbortController();
  const waiting=waitForEmailCode(directory,keyPath,controller.signal,3000);
  const rejected=assert.rejects(waiting);
  await pending(directory);controller.abort();await rejected;
  await assert.rejects(access(path.join(directory,'otp-request.json')));
});
for(const tampered of [false,true])await fixture(async(directory,keyPath,key)=>{
  const waiting=waitForEmailCode(directory,keyPath,undefined,3000),rejected=assert.rejects(waiting);
  const request=await pending(directory);
  const blob=seal(key,{request_id:tampered?request.id:'0'.repeat(32),code:'246810'});
  if(tampered)blob[blob.length-1]^=1;
  await writeFile(path.join(directory,'otp-response.enc'),blob);await rejected;
  await assert.rejects(access(path.join(directory,'otp-response.enc')));
});
await fixture(async(directory,keyPath,key)=>{
  let deadline;
  for(let attempt=1;attempt<=3;attempt++){
    const waiting=waitForEmailCode(directory,keyPath,undefined,3000,attempt===1?'initial':'incorrect',5000);
    const request=await pending(directory);
    assert.equal(request.attempt,attempt);
    if(deadline)assert.equal(request.deadline_at,deadline);else deadline=request.deadline_at;
    if(attempt===1)await assert.rejects(waitForEmailCode(directory,keyPath,undefined,10));
    await writeFile(path.join(directory,'otp-response.enc'),seal(key,{request_id:request.id,code:'246810'}));
    assert.equal(await waiting,'246810');
  }
  await assert.rejects(waitForEmailCode(directory,keyPath,undefined,3000,'incorrect',5000),/limit/);
});
await fixture(async(directory,keyPath,key)=>{
  const waiting=waitForEmailCode(directory,keyPath,undefined,3000,'initial',5000);
  const rejected=assert.rejects(waiting,EmailResendRequested);
  const request=await pending(directory);
  await writeFile(path.join(directory,'otp-response.enc'),seal(key,{request_id:request.id,action:'resend'}));
  await rejected;
  const second=waitForEmailCode(directory,keyPath,undefined,3000,'after_resend',5000);
  const next=await pending(directory);assert.equal(next.attempt,2);assert.notEqual(next.id,request.id);
  assert.equal(next.deadline_at,request.deadline_at);
  await writeFile(path.join(directory,'otp-response.enc'),seal(key,{request_id:next.id,code:'135790'}));
  assert.equal(await second,'135790');
});
console.log('PASS: encrypted code delivery; bounded correction rounds; operator resend; shared deadline; concurrent/replay/tamper rejection; timeout/cancel');
