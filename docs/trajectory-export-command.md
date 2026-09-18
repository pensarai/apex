# Export a recorded trajectory

`pensar export-trajectory` converts saved Apex native rollout evidence into a
validated ATIF bundle. It reads existing files only and does not start an agent,
model, tool, provider, TUI, or telemetry runtime.

```bash
pensar export-trajectory \
  --input ./trajectory-export.json \
  --output ./exports/run-123
```

The input is a strict version 1 JSON document. Relative source paths resolve
from the input file's directory.

```json
{
  "version": 1,
  "sources": [
    {
      "id": "attempt-001",
      "path": "./evidence/attempt-001.json",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "sizeBytes": 1234
    }
  ],
  "rootSourceId": "attempt-001",
  "agent": { "name": "apex", "version": "2.5.0" },
  "exporter": { "name": "apex-native-evidence", "version": "1" }
}
```

The command validates every declared source identity and the complete bundle
with bounded reads before creating the output directory. The destination must
not exist. Files are created exclusively, and `trajectory-bundle.json` is written last
as the commit marker. If a write fails, the command removes only the fresh
directory it created. A directory without `trajectory-bundle.json` is not a completed
export.

The optional `independentValidation` field records a result supplied by the
caller. A `failed` result blocks publication, while omission is recorded as
`not_run`. The command does not invoke an external validator.

Success prints one JSON object containing `outputDirectory`, `manifestPath`,
`rootTrajectoryId`, and `fileCount`. The bundle preserves exact source evidence
alongside its ATIF documents and content-addressed assets.
