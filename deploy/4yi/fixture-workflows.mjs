// Synthetic orchestration fixtures only: no activities, model calls or network targets.
export async function fixtureCompleted() {
  return {status: 'completed', partialReasons: []};
}
export async function fixturePending() {
  await new Promise(() => {});
}
