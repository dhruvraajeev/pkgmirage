import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";

// vitest.config.ts reads the migrations (in Node) and passes them in; the binding exists only in tests, so it stays
// out of the Worker's Env type.
await applyD1Migrations(env.DB, (env as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS);
