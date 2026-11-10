/** Retry only an uncommitted provider response, never an agent or tool execution. */
import { createAssistantMessageEventStream } from '@earendil-works/pi-ai';
import type { StreamFn } from '@earendil-works/pi-agent-core';
import { setTimeout as delay } from 'node:timers/promises';

const INTERRUPTED = /upstream stream interrupted|premature[_ ]eof/i;

export function retryInterruptedStream(stream: StreamFn): StreamFn {
  return async (model, context, options) => {
    for (let attempt = 0; ; attempt++) {
      // Keep partial text/tool arguments outside the agent transcript. The agent
      // receives exactly one terminal message and can execute tools only then.
      const response = await stream(model, context, options);
      const message = await response.result();
      if (model.provider === 'fouryi' && message.stopReason === 'error'
          && INTERRUPTED.test(message.errorMessage ?? '') && attempt < 2
          && !options?.signal?.aborted) {
        const waitMs = 1000 * 2 ** attempt;
        console.log(`Provider stream interrupted; retrying current model call ${attempt + 1}/2 after ${waitMs}ms; partial response discarded`);
        await delay(waitMs, undefined, options?.signal ? { signal: options.signal } : undefined);
        continue;
      }
      if (message.stopReason === 'pending') throw new Error('Provider response ended without terminal status');
      const output = createAssistantMessageEventStream();
      if (message.stopReason === 'error' || message.stopReason === 'aborted') {
        output.push({ type: 'error', reason: message.stopReason, error: message });
      } else {
        output.push({ type: 'done', reason: message.stopReason, message });
      }
      return output;
    }
  };
}
