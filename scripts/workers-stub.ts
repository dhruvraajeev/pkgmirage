// Stands in for the Workers runtime module when the engine runs under Node (scripts/eval.ts). The evaluation passes no
// watchlist, so nothing is ever handed to waitUntil.
export const waitUntil = (promise: Promise<unknown>) => void promise.catch(() => {});
export const env = {};
