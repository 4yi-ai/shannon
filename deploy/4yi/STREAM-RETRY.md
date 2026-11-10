# Interrupted model response retries

The `fouryi` provider retries an assistant response ending in `error` with
`Upstream stream interrupted` or `premature_eof` up to twice, waiting 1 and 2
seconds. This wraps the Pi stream function, not `session.prompt` or a Temporal
activity. Previous completed tool results remain in the request context. Failed
partial text and tool calls never enter the agent transcript or tool executor.
Only the final response is delivered to the Agent; per-response token deltas are
not exposed on this path. Exhaustion returns the final error normally. Abort
cancels backoff and is never retried. Other errors keep their existing policy.
Vendor SDK request retries are separate and unchanged.

Retries can incur additional model charges, including upstream work before a
broken stream. They do not fix the gateway's underlying EOF. This only guarantees
no replay by this local retry wrapper; it cannot roll back remote model work.

Verification uses the real pinned Agent loop and synthetic provider streams:
`node deploy/4yi/test-stream-retry.mjs` after building the Worker. It tests a
completed tool followed by a failed partial tool response and successful retry,
retry exhaustion, non-transport failures, and cancellation during backoff. No
paid model or scan target is contacted.
