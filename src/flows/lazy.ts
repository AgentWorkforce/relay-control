/** Construct optional Flows storage only on a protocol/credential request. */
export function lazyFlowsStore<T>(create: () => T): () => T {
  let initialized = false;
  let instance: T;
  return () => {
    if (!initialized) { instance = create(); initialized = true; }
    return instance!;
  };
}
