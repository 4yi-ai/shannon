// Run in the Web container against the SQL-backed service; never runs a scanner.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(new URL('../../apps/worker/package.json', import.meta.url));
const { Client, Connection } = require('@temporalio/client');
const { Worker, NativeConnection } = require('@temporalio/worker');
const address = process.env.TEMPORAL_ADDRESS || 'localhost:7233';
const connection = await Connection.connect({address});
const client = new Client({connection});
let native;
try {
  if (process.argv[2] === 'verify') {
    const handle = client.workflow.getHandle(process.argv[3]);
    assert.equal((await handle.describe()).status.name, 'RUNNING');
    await handle.terminate('Synthetic persistence test finished');
    assert.equal((await handle.describe()).status.name, 'TERMINATED');
    console.log('PASS: workflow survived Temporal restart and termination was durable');
  } else {
    native = await NativeConnection.connect({address});
    const taskQueue = 'standalone-fixture-' + randomUUID();
    const worker = await Worker.create({connection:native, namespace:'default', taskQueue,
      workflowsPath:fileURLToPath(new URL('./fixture-workflows.mjs', import.meta.url)),
      bundlerOptions:{webpackConfigHook(config) {
        config.resolve.modules.unshift(fileURLToPath(new URL('../../apps/worker/node_modules', import.meta.url)));
        return config;
      }}});
    const done = worker.run();
    try {
      const completed = await client.workflow.start('fixtureCompleted',{taskQueue,workflowId:'completed-'+randomUUID()});
      assert.equal((await completed.result()).status,'completed');
      const pending = await client.workflow.start('fixturePending',{taskQueue,workflowId:'pending-'+randomUUID()});
      assert.equal((await pending.describe()).status.name,'RUNNING');
      console.log('PENDING_WORKFLOW='+pending.workflowId);
    } finally {
      worker.shutdown();
      await done;
    }
  }
} finally {
  await connection.close();
  if(native) await native.close();
}
