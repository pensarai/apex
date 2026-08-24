# H7 — Apex briefing (`__` private params)

HackerOne: vercel_sandbox. Only `https://api.vercel.com` `/v2|/v3|/v4/sandboxes*`. Cap 5 rps. Stop at confirmation. Do not print tokens. Python urllib needs `allow_unprotected: true`. `{host}` in Python format strings trips the scope guard.

**One hypothesis. One worker. No exploratory spawn. Stop at the kill-gate.**

Absolute path: `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/target-h7-briefing.md`

## Hypothesis

Vendored `getPrivateParams` (`types.js`) forwards every key starting with `__` into create/fork JSON and get query (`sandbox.js` / `api-client.js`). Regular `teamId` / `projectId` stay on the query pair. If the **server** binds `__teamId` / `__projectId` / `__snapshotId` as aliases that override that pair, this is Target #9 with a new key (cross-tenant read/create).

Client-only forwarding is unpaid. Finding only if a `__*` key changes which tenant/project/object the server acts on.

## Kill-gate (stop if all hold)

- GET with extra `__teamId` / `__projectId` is **400** (unknown property) **or 200** that still returns the object named by the real `teamId`/`projectId`/`name`
- GET that would 403/404 without `__` still 403/404 with `__teamId`/`__projectId` of the owner (same oracle as Target #9)
- One create (only if GET did **not** 400): body `__projectId` / `__teamId` of B is ignored or 400; new sandbox is in Account A

## Do not re-prove

- Target #9 `teamId`/`projectId` pair matrix **without** `__` keys
- Target #1 BOLA 403/404 without `__`
- H1–H6

## Live objects (re-GET; do not `POST /stop` or snapshot)

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`, A2 `prj_7uASgsVYJvWLTU8aWVtm059LlSoZ`.

- Named GET target: `h3-src-a` (or `victim-base` if h3-src-a 404s). Last session `sbx_CJ2wENwidC9YzSyD5zSU943qcM7S`
- Do **not** DELETE `h3-src-a` / `h3-obs-a` / `fw-victim` / `victim-base`

Account B: team `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`. Named `fw-observer`. PAT in `.apex/bug-bounty/local/headers-b.json`.

Session headers = Account A.

## Confirmed wire (SDK)

GET query (plus constructor `teamId`):

```
GET /v2/sandboxes/{name}?teamId=&projectId=&resume=true&__teamId=&__projectId=
```

Create body (`POST /v3/sandboxes`; `projectId` **in the body**):

```json
{
  "projectId": "prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5",
  "name": "h7-throwaway",
  "timeout": 300000,
  "__projectId": "prj_fuEcV8s1ISZBg4LncdBK1MfScxb9",
  "__teamId": "team_LO7V6PmnTOI8i66m8MO6g6yb"
}
```

Do not POST `forwardRules`. Do not `POST /network-policy` `{}`. Do not snapshot keep-list sandboxes.

## Objectives (this is the only objective)

1. **GET ignore / bind:** `GET /v2/sandboxes/h3-src-a?teamId=A&projectId=A&__teamId=B&__projectId=B` with A token. Expect 200 A’s object (id/name/project still A) or 400. Finding = 403/404 **because of** `__`, or a B/A2 object.
2. **GET cannot override a failing pair:** `GET /v2/sandboxes/h3-src-a?teamId=B&projectId=B&__teamId=A&__projectId=A` with A token. Expect 403 (same as Target #9 A+B team). Finding = 200 A’s object.
3. **GET cannot open B’s name via `__`:** `GET /v2/sandboxes/fw-observer?teamId=A&projectId=A&__teamId=B&__projectId=B` with A token. Expect 404 named sandbox not in this project. Finding = 200 B’s object.
4. **Create only if step 1 was not 400:** `POST /v3/sandboxes` with A token, A `projectId` in body, plus `__projectId`/`__teamId` of B, name `h7-throwaway`. Expect 400 or 200 in **A**. Finding = sandbox in B’s team/project. If 200 in A, `DELETE` `h7-throwaway` only. Stop; do not fork-sweep.
5. Call `response`. Do **not** spawn a second worker.

Optional one-shot if steps 1–2 are ignore-200: same GET with `__projectId=A2` (A team + A project). Expect still A’s object. Finding = A2 object.

## Finding vs not

- **Finding:** `__*` changes tenant/project/object (200 on a foreign name, create in B, or `__` repairs a pair that should 403/404).
- **Not a finding:** 400 unknown property; extra keys ignored; same 403/404 as Target #9; client forwarding `__` without server bind.

Read also: `.apex/bug-bounty/whitebox-hypotheses.md`, `.apex/bug-bounty/target-9-briefing.md`.
