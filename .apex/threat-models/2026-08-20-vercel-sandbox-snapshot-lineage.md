# Threat model — Target #7: snapshot / fork content lineage

Generated for Apex `/triage`. Scope is whether the snapshot store returns the **wrong disk**. Not session BOLA (Target #1). Not firewall (Target #3/#6). Not inbound routes (Target #4). Not VMM (Target #5).

## System

`POST /v3/sandboxes/sessions/{id}/snapshot` checkpoints guest disk (stops the session). Fork (`POST /v3/sandboxes/{name}/fork`) and create (`POST /v4/sandboxes` `{source:{type:"snapshot", snapshotId}}`) boot a child from that checkpoint. Snapshots are listed with `GET /v2/sandboxes/snapshots?project=`.

## Trust boundaries

1. **Snapshot id → owning project.** A `snapshotId` from project A must not restore into project B (other team or same-team A2).
2. **Content ↔ id.** Restore of snapshot X must contain X’s canary, never Y’s, including after concurrent snapshots (cache/dedup).
3. **Name → project.** Fork of a victim name plus attacker `projectId` must not clone victim disk.
4. **PATCH graft.** `currentSnapshotId` on a named sandbox the caller owns must reject foreign snapshots.

## Closed 20 Aug 2026 (do not reopen)

Own fork/restore keeps own canary. Foreign GET 403/404. Foreign create 404. Same-team cross-project restore 404 (project-scoped). Foreign PATCH 404. B PATCH 403. Cursor replay 400 `invalid_cursor`. No A/B canary mix on resume.
