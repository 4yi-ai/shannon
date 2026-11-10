// Real pinned Agent loop, synthetic responses; no target or paid model calls.
import assert from 'node:assert/strict';
import { Agent } from '../../apps/worker/node_modules/@earendil-works/pi-agent-core/dist/index.js';
import { createAssistantMessageEventStream } from '../../apps/worker/node_modules/@earendil-works/pi-ai/dist/index.js';
import { retryInterruptedStream } from '../../apps/worker/dist/ai/pi/stream-retry.js';
const model={provider:'fouryi',id:'fixture',api:'openai-completions',name:'fixture',baseUrl:'http://fixture',reasoning:false,input:['text'],contextWindow:10000,maxTokens:1000,cost:{input:0,output:0,cacheRead:0,cacheWrite:0}};
function message(stopReason,content=[],errorMessage){return {role:'assistant',provider:'fouryi',model:'fixture',api:'openai-completions',content,stopReason,errorMessage,timestamp:1,usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};}
function result(value){const s=createAssistantMessageEventStream();s.push(value.stopReason==='error'?{type:'error',reason:'error',error:value}:{type:'done',reason:value.stopReason,message:value});return s;}
const tool=id=>({type:'toolCall',id,name:'inspect',arguments:{}});
let calls=0,executions=0;
const agent=new Agent({initialState:{model,tools:[{name:'inspect',label:'inspect',description:'fixture',parameters:{type:'object',properties:{}},execute:async()=>{executions++;return {content:[{type:'text',text:'already-completed-tool'}],details:{}};}}]},streamFn:retryInterruptedStream((_model,context)=>{
 calls++;
 if(calls===1)return result(message('toolUse',[tool('first')]));
 assert(context.messages.some(m=>m.role==='toolResult'&&m.toolCallId==='first'));
 assert(!context.messages.some(m=>m.role==='assistant'&&m.stopReason==='error'));
 if(calls===2)return result(message('error',[tool('discarded')],'Upstream stream interrupted [premature_eof]'));
 return result(message('stop',[{type:'text',text:'done'}]));
})});
await agent.prompt('fixture');assert.equal(calls,3);assert.equal(executions,1);
assert(!JSON.stringify(agent.state.messages).includes('discarded'));
let exhausted=0;
const final=await retryInterruptedStream(()=>{exhausted++;return result(message('error',[],'premature_eof'));})(model,{messages:[]});
assert.equal((await final.result()).stopReason,'error');assert.equal(exhausted,3);
for(const error of ['401 invalid credentials','context window exceeded','quota exhausted']){
 let count=0;await (await retryInterruptedStream(()=>{count++;return result(message('error',[],error));})(model,{messages:[]})).result();assert.equal(count,1);
}
const controller=new AbortController();let aborted=0;
const pending=retryInterruptedStream(()=>{aborted++;controller.abort();return result(message('aborted'));})(model,{messages:[]},{signal:controller.signal});
assert.equal((await(await pending).result()).stopReason,'aborted');assert.equal(aborted,1);
const backoffAbort=new AbortController();let backoffCalls=0;
const backingOff=retryInterruptedStream(()=>{backoffCalls++;return result(message('error',[],'premature_eof'));})(model,{messages:[]},{signal:backoffAbort.signal});
setTimeout(()=>backoffAbort.abort(),20);
await assert.rejects(backingOff,{name:'AbortError'});assert.equal(backoffCalls,1);
console.log('PASS: bounded call retry, retained tool result, no replay or partial tool execution, terminal errors and cancellation');
