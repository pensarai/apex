# Bundled Wordlists

These wordlists ship with `@pensar/apex` so the agent has guaranteed access to a known-good `-w` argument for tools like `gobuster`, `ffuf`, `dirb`, `wfuzz`, and `dirsearch` regardless of host. Without this bundle, the agent tends to reach for `/usr/share/wordlists/dirb/common.txt` (a Kali-only path) and fails on macOS, Alpine, vanilla Linux, and most Docker base images.

See issue [#642](https://github.com/pensarai/apex/issues/642) for the full motivation.

## Tiers

| File         | Entries | Size   | When to use                                                               |
| ------------ | ------- | ------ | ------------------------------------------------------------------------- |
| `tiny.txt`   | ~200    | ~3KB   | Sub-second smoke probe, time-pressured runs, first-pass triage            |
| `common.txt` | ~4.7k   | ~38KB  | Default for normal recon                                                  |
| `large.txt`  | ~30k    | ~250KB | Escalation when `common.txt` finished and target still looks under-mapped |

The agent picks a tier based on signals (time budget, user intent, completeness of prior recon) — it does NOT chain tiers automatically. See `src/core/agents/specialized/utils.ts` (`detectOSAndEnhancePrompt`) for the policy injected into the system prompt.

## Provenance

- **`common.txt`** — verbatim copy of [`SecLists/Discovery/Web-Content/common.txt`](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt)
- **`large.txt`** — verbatim copy of [`SecLists/Discovery/Web-Content/raft-medium-directories.txt`](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-directories.txt)
- **`tiny.txt`** — custom-curated. Combines the most-frequently-hit paths from `common.txt` with a fixed core of high-signal security paths (`.git/config`, `.env*`, `.well-known/security.txt`, `actuator/env`, `swagger.json`, `openapi.json`, `graphql`, `wp-config.php`, etc.). Designed to maximise hits-per-request when budget is tight; not derived from `common.txt` alone — see the file for the curation.
- **`LICENSE`** — verbatim copy of the [SecLists MIT license](https://github.com/danielmiessler/SecLists/blob/master/LICENSE), preserved here to satisfy attribution for the entries we redistribute.

## Updating

To pull fresh upstream copies:

```bash
curl -fsSL -o assets/wordlists/common.txt \
  'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt'

curl -fsSL -o assets/wordlists/large.txt \
  'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt'
```

Then re-run `bun run test` — the wordlist tests assert size invariants (`tiny < common < large` and `tiny.txt` in the 150–300 range) so accidental drift fails the build.
