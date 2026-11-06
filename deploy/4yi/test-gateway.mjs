// Protocol contract test with the actual pinned Pi runtime; no external model traffic.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { ModelRuntime } from '../../apps/worker/node_modules/@earendil-works/pi-coding-agent/dist/index.js';
const directory = await mkdtemp(path.join(tmpdir(), 'shannon-gateway-'));
let calls = 0;
const server = createServer(async (request, response) => {
  try {
    assert.equal(request.url, '/api/v1/chat/completions');
    assert.equal(request.headers.authorization, 'Bearer fixture-instance-token');
    let raw = ''; for await (const chunk of request) raw += chunk;
    const body = JSON.parse(raw);
    assert.equal(body.model, 'fixture-model');
    assert.equal(body.store, undefined);
    assert.equal(body.reasoning_effort, undefined);
    assert.equal(body.stream, true);
    assert.ok(body.tools?.length > 0);
    if (calls === 1) assert.ok(body.messages.some(message => message.role === 'tool' && message.content === 'tool-result'));
    response.writeHead(200, { 'Content-Type': 'text/event-stream' });
    const delta = calls === 0 ? {role:'assistant', tool_calls:[{index:0,id:'call_fixture',type:'function',function:{name:'inspect',arguments:'{"path":"src"}'}}]} : {role:'assistant',content:'verified'};
    const reason = calls === 0 ? 'tool_calls' : 'stop'; calls++;
    response.end('data: '+JSON.stringify({id:'fixture',object:'chat.completion.chunk',created:1,model:'fixture-model',choices:[{index:0,delta,finish_reason:reason}],usage:{prompt_tokens:10,completion_tokens:3,total_tokens:13}})+'\n\ndata: [DONE]\n\n');
  } catch (error) {
    response.writeHead(500); response.end(String(error));
  }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
try {
  const base = `http://127.0.0.1:${server.address().port}/api/v1`;
  const config = execFileSync('python3', ['-B','-c','import json,sys; from apps.standalone.models import gateway_config; print(json.dumps(gateway_config("fixture-model",sys.argv[1])))',base]);
  const modelsPath = path.join(directory,'models.json'); await writeFile(modelsPath,config);
  const credentials = {read:async()=>({type:'api_key',key:'fixture-instance-token'}), list:async()=>[], modify:async()=>undefined, delete:async()=>{}};
  const runtime = await ModelRuntime.create({modelsPath,modelsStorePath:path.join(directory,'store.json'),allowModelNetwork:false,credentials});
  const model = runtime.getModel('fouryi','fixture-model');
  assert.ok(model, 'Custom gateway model must resolve');
  assert.equal(model.api,'openai-completions');
  const context = {messages:[{role:'user',content:'Inspect source',timestamp:Date.now()}],tools:[{name:'inspect',description:'Inspect a path',parameters:{type:'object',properties:{path:{type:'string'}},required:['path']}}]};
  const first = await runtime.completeSimple(model,context,{maxTokens:128});
  assert.equal(first.stopReason,'toolUse');
  const call = first.content.find(item=>item.type==='toolCall'); assert.equal(call.name,'inspect');
  context.messages.push(first,{role:'toolResult',toolCallId:call.id,toolName:'inspect',content:[{type:'text',text:'tool-result'}],isError:false,timestamp:Date.now()});
  const second = await runtime.completeSimple(model,context,{maxTokens:128});
  assert.equal(second.stopReason,'stop'); assert.equal(second.content[0].text,'verified'); assert.equal(calls,2);
  console.log('PASS: custom registry, instance auth, Chat Completions SSE, tool call and tool result');
} finally {
  server.close(); await rm(directory,{recursive:true,force:true});
}
