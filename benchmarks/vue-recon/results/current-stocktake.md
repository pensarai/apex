# Vue Recon Baseline Stocktake

Baseline command:

```bash
bun run benchmark:vue-recon
```

## Result

| Metric               | Current baseline |
| -------------------- | ---------------: |
| Fixtures             |                3 |
| Page route recall    |             0.0% |
| API endpoint recall  |             0.0% |
| Dynamic route recall |             0.0% |
| False positives      |                0 |

## What current recon saw

- `extractJavascriptEndpoints` found each app's external production bundle:
  - `/_nuxt/app-nuxt-r4t5y6.js`
  - `/assets/app-api-q1w2e3.js`
  - `/assets/app-router-a1b2c3.js`
- It did not analyze those external bundles, so it reported zero endpoints.
- `mapAppWithSurface` returned `fallback` for all three apps with reason
  `no frameworks detected`.

## Coverage gaps proven by the benchmark

- Vue Router page routes are not deterministically extracted.
- Vite hashed external chunks are not parsed by the current JS extractor.
- Nuxt file-based pages and `server/api` routes are not covered by the current
  surface integration.
- `$fetch`, `useFetch`, axios instances, `import.meta.env` API bases, and
  template-literal dynamic API paths are not covered by the deterministic
  baseline.

## Build priorities implied by the data

1. Fetch and analyze same-origin external JS bundles in `jsExtraction.ts`.
2. Add route/API patterns for Vue Router, Nuxt `$fetch` / `useFetch`, axios
   instances, and `import.meta.env` API bases.
3. Add Vue/Nuxt whitebox coverage through `@pensar/surface` or an Apex fallback
   extractor.
4. Feed this endpoint-oracle format into evalgate/full attack-surface runs so
   LLM-driven browser exploration can be scored against the same manifests.
