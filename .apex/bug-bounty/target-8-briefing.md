# Target #8 — Drives beta (retired unless access lands)

HackerOne program: vercel_sandbox. Drives are persistent attachable volumes (`POST /v2/sandboxes/drives/{name}` get-or-create, list, delete, mount). Foreign-drive IDOR would be Critical.

## Access gate (2026-08-20)

- Changelog: private beta, **Pro and Enterprise only**, waitlist https://vercel.typeform.com/to/F19n6v2q (from https://vercel.com/changelog/drives-for-vercel-sandbox-in-private-beta).
- Docs: https://vercel.com/docs/sandbox/concepts/drives — Hobby is not eligible.
- Target #5 already observed drive list/get-or-create **403 (private beta)** and mounts **404**.

This engagement’s accounts are **Hobby**. Without Pro + waitlist approval, foreign-drive IDOR is untestable. Do not spend Apex workers re-probing 403/404.

## If access appears

1. Create drive `h1-drive-a` on Account A with a canary file mounted at `/workspace/SECRET.txt`.
2. Account B: `GET/POST /v2/sandboxes/drives/{name}` with A’s name and with guessed ids. Finding = 200 that reads/mounts A’s drive.
3. Same-team A2 project vs A victim project: name collision / mount of the other project’s drive.
4. Stop at confirmation. Do not dump customer data.

Until then: **retired / untestable**. Re-open only after Pro + beta on Account A.

## Probe (20 Aug 2026) — retired

Account A and B Hobby tokens:

- `POST /v2/sandboxes/drives/{name}` and `GET /v2/sandboxes/drives` → **403** `Drives are in private beta. Register your interest…` (changelog waitlist).
- `/v3` and `/v4` drives → 404 Not Found.
- B `POST` A’s drive name + A `teamId` → 403 Not authorized (authz gate, not a beta bypass).
- B + A `projectId` + B `teamId` → 404 Could not find project.

Hobby is not eligible (Pro/Enterprise + waitlist). **Retired / untestable.** Researcher may submit https://vercel.typeform.com/to/F19n6v2q after a Pro upgrade; do not spend Apex workers re-probing 403.

Waitlist URL (no Hobby unlock expected): https://vercel.typeform.com/to/F19n6v2q
Changelog: https://vercel.com/changelog/drives-for-vercel-sandbox-in-private-beta
Docs: https://vercel.com/docs/sandbox/concepts/drives
