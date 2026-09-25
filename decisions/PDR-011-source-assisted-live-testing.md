# PDR-011: Optional source access for live penetration testing

## Context

Agents running in Daytona should be able to inspect source without cloning a
repository into each agent sandbox. Local users need the same exploration
interface against an existing checkout. Source access must preserve live testing
coverage and the requirement for evidence of deployed impact.

## Decision

The host supplies a `SourceProvider` bound to one authorized repository or remote
snapshot. The agent uses four methods through code mode:

- `tools.source.describe()` identifies the repository and available revision.
- `tools.source.listTree({ path?, offset?, limit? })` pages directory children.
- `tools.source.search({ query, path?, limit? })` performs bounded, literal,
  case-sensitive searches and reports incomplete results.
- `tools.source.readFile({ path, offset?, limit?, version? })` pages file contents.

These methods use the existing canonical capability bridge, including validation,
approval wrapping, cancellation, and trace events. Their schemas are nested in
code mode. The explicit direct-tool compatibility mode retains ordinary schemas.
Repository contents are untrusted data. Access is optional and independent of the
agent's working directory; there is no fallback to arbitrary local source.

`LocalSourceProvider` reads an existing checkout. An injected `sourceProvider`
takes precedence over the existing `session.config.codebasePath` local setting.
Pentest workflows also accept the existing `cwd` input. Providers are passed to
delegated pentest workers. The source methods have no write or process-execution
capability.

Fast Strike, engagement leads, mission workers, and targeted pentest agents may
use source to form hypotheses. They must continue exploring runtime and deployment
behavior independently. Live validation against the assigned target is the final
oracle. Source-only evidence cannot settle a Fast Strike or grouped mission result
as `impact-proven`; source references may accompany live observations. The finding
judge still evaluates whether the actual target behavior proves the claimed impact.
Tool provenance alone cannot establish that a shell script genuinely tested a target.

## Provider Contract

The exported `SourceProvider` type and `LocalSourceProvider` are available through
`src/core/api`. A local programmatic caller can set:

```ts
sourceProvider: new LocalSourceProvider("/path/to/repository");
```

Remote hosts implement the same four methods using their authenticated RPC client.
The provider, not the model, owns credentials, repository scope, and snapshot
selection. Remote `describe()` includes an immutable revision identifier. Remote
implementations must enforce request bounds and cancellation, use repository-relative
paths, and honor `readFile.version` so pages cannot silently cross revisions.
The host must restore the same snapshot binding on engagement resume.

Local file pages carry content hashes. Supplying the previous page's `version`
detects edits between reads; a working tree is not an immutable snapshot. Local
search skips `.git`, `node_modules`, and symlinks, examines at most 20,000 files,
and reports truncation and skipped files. File reads support UTF-8 text up to
2 MiB. Read offsets use JavaScript string indices. These limits are explicit;
an incomplete search is not evidence that no matching code exists.

## Scope

This change implements the Apex interface and local provider. Console still needs
the remote snapshot store, scoped agent-RPC operations, and an adapter implementing
`SourceProvider`; no source-store service or Daytona deployment is included here.

Checkout-based discovery and patching tools remain for their existing callers.
Fast Strike and engagement leads use the minimal source interface for repository
orientation and searches. Remote scanners, structural search engines, and migration
of whitebox discovery are separate work.

## Alternatives Considered

- Clone into every agent sandbox: increases storage and setup costs for large repos.
- Expose another set of top-level source tools in code mode: duplicates the existing
  capability bridge and expands the model-facing schema surface.
- Treat source analysis as live-test completion: cannot establish deployment
  reachability, runtime configuration, or demonstrated impact.
