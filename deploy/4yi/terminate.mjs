import { createRequire } from 'node:module';
const require = createRequire(new URL('../../apps/worker/package.json', import.meta.url));
const { Client, Connection, WorkflowNotFoundError } = require('@temporalio/client');
const connection = await Connection.connect({ address: process.env.TEMPORAL_ADDRESS || 'localhost:7233' });
try {
  if (['--health', '--bootstrap'].includes(process.argv[2])) {
    await connection.workflowService.getSystemInfo({});
    try {
      await connection.workflowService.describeNamespace({ namespace: 'default' });
    } catch (error) {
      if (process.argv[2] !== '--bootstrap' || error.code !== 5) throw error;
      try {
        await connection.workflowService.registerNamespace({ namespace: 'default', workflowExecutionRetentionPeriod: { seconds: 604800 } });
      } catch (registrationError) {
        if (registrationError.code !== 6) throw registrationError;
      }
    }
    process.exitCode = 0;
  } else {
  const handle = new Client({ connection }).workflow.getHandle(process.argv[2]);
  try {
    if ((await handle.describe()).status.name === 'RUNNING') await handle.terminate('Cancelled by standalone supervisor');
  } catch (error) {
    if (!(error instanceof WorkflowNotFoundError)) throw error;
  }
  }
} finally {
  await connection.close();
}
