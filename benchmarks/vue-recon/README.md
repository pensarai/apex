# Vue Recon Benchmarks

This suite measures Apex recon coverage against buildable Vue-style applications
before Vue-specific recon improvements are made.

The fixtures are intentionally small and include a machine-readable endpoint
oracle. They are designed for evalgate-style consumers and for local baseline
runs through:

```bash
bun run benchmark:vue-recon
```

## Fixtures

- `vue-vite-router` — Vue 3 + Vite + Vue Router page routes, dynamic routes,
  nested routes, and lazy-loaded route chunks.
- `vue-vite-api-calls` — Vue 3 + Vite API calls through `fetch`, axios-style
  clients, environment-derived API bases, and relative paths.
- `nuxt-routes-api` — Nuxt-style pages, dynamic pages, `server/api` routes, and
  `$fetch` / `useFetch` calls.
- `vue-enterprise-mock` — Runnable local Vue-style SPA plus Bun API server used
  for full Apex pentest comparison.

Each app has:

- source files under `apps/<id>/`
- a static production-like build under `apps/<id>/static-build/`
- an expected endpoint manifest under `expected/<id>.json`

## Baseline metric sources

The current local baseline script does not run model-backed recon. It measures
the deterministic pieces Apex already has locally:

- blackbox JavaScript extraction via `extractJavascriptEndpoints`
- whitebox deterministic route mapping via `mapAppWithSurface`

This keeps the benchmark repeatable without API keys and gives evalgate an
endpoint oracle to compare against when running full `pensar pentest` or
attack-surface sessions.

## Full Apex pentest result

`vue-enterprise-mock` was also exercised through the full Apex CLI pentest
workflow. That run discovered all known first-party endpoints through persisted
`document_endpoint` assets. See:

- `results/vue-enterprise-mock-pentest.md`
- `results/vue-enterprise-mock-pentest.json`
