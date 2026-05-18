---
name: create-skill
description: Create a new agent skill — global personal, project-personal, or project-team. Surveys existing skills, checks for overlap, handles the .claude/skills/ symlink and .gitignore whitelist for project skills. Use when you want to formalize a workflow or instruction set.
argument-hint: "[name or short description of what the skill should do]"
allowed-tools: Bash(git add *) Bash(ln *) Bash(mkdir *) Bash(cat *) Bash(ls *) Bash(find *) Bash(~/.claude/scripts/sync-agent-skills.sh)
---

# Create a skill

You are creating a new agent skill. Skills are reusable instructions stored as `SKILL.md` files following the [Agent Skills spec](https://agentskills.io/specification). Follow these steps exactly.

## Step 0: Pick the mode

Ask the user where the skill should live, using `AskUserQuestion` with three options:

- **Global personal** — `~/.agents/skills/<name>/`. Available in every project on this machine; not shared with anyone.
- **Project team-shared** — `<repo>/.agents/skills/<name>/`. Committed to the repo; available to every contributor. Use when the workflow generalizes to the whole team.
- **Project personal** — `<repo>/.agents/skills/<name>/` but gitignored. Local to this working tree; won't be shared or pushed.

Branch based on the answer. The bar is highest for team-shared — keep that scope focused.

## Step 1: Verify scaffolding

- **Global mode**: confirm `~/.agents/skills/` exists.
- **Project modes**: confirm `<repo>/.agents/skills/` and `<repo>/.claude/skills/` are real directories, and the repo's `.gitignore` has the skills block (look for `.agents/skills/*`). If missing, stop and point the user to AGENTS.md's "Skills" section — the repo isn't scaffolded yet.

## Step 2: Survey existing skills

Read the frontmatter (`name` + `description`) of every `SKILL.md` in the chosen scope:

- **Global mode**: `~/.agents/skills/*/SKILL.md`.
- **Project modes**: `<repo>/.agents/skills/*/SKILL.md`. Also briefly scan `~/.agents/skills/` so you can flag if the contributor already has a personal skill for this concept.

Print a one-line summary per skill so the user can see what already exists.

## Step 3: Gather the request

Take the argument (if any) or ask the user:

- **Rough idea** — what workflow or instruction set is this codifying?
- **Name** — kebab-case, lowercase, 1–64 chars, no leading/trailing/consecutive hyphens (per spec). **Avoid generic names** (`add`, `list`, `run`, `check`, `review`) — they collide across tools and plugins. For global personal skills consider prefixing with your handle (e.g. `jraad-foo`) to keep the team-skill short-name slot open.
- **Description** — one line, says both _what_ it does and _when_ to use it. The agent uses this to decide when to invoke.
- **Arguments** — optional; what does the user pass after `/<name>`?
- **Helper scripts/files** — optional; does the skill need bash scripts or reference files alongside `SKILL.md`?

## Step 4: Overlap check

Compare the proposal to the surveyed skills. If a near-match exists, surface it (name + description) and ask:

- **Extend** the existing skill instead of creating a new one?
- **Split** — keep the existing skill focused, create a new one for the distinct part?
- **Proceed** with a clearly distinct scope?

For project team-shared, lean harder against duplication — discoverability beats specificity in a shared library.

## Step 5: Design

Present the proposed `SKILL.md` for approval **before** writing anything:

```
---
name: <name>
description: <one-line>
argument-hint: "<args>"           # if any
allowed-tools: <tools>            # if the skill runs bash
---

# <Title>

Body outline: numbered steps, what each does, where it asks the user, what it produces.
```

Get explicit approval. Iterate if the user wants changes.

## Step 6: Write

Branch by mode:

**Global personal**

1. `mkdir ~/.agents/skills/<name>` and write `SKILL.md`.
2. Run `~/.claude/scripts/sync-agent-skills.sh` to create the Claude Code compat symlink in `~/.claude/skills/<name>`.

**Project team-shared**

1. `mkdir <repo>/.agents/skills/<name>` and write `SKILL.md`.
2. `ln -s ../../.agents/skills/<name> <repo>/.claude/skills/<name>` (relative target — worktree-safe).
3. Edit `<repo>/.gitignore`: add two whitelist lines next to the existing skills block.
   ```
   !.agents/skills/<name>/
   !.claude/skills/<name>
   ```
4. `git add .agents/skills/<name>/ .claude/skills/<name> .gitignore` — stage only the new content, leave the user to commit.

**Project personal**
Same as project team-shared, **minus step 3 and step 4**. The existing `.agents/skills/*` ignore pattern already keeps the new skill out of git.

## Step 7: Confirm

Report:

- Skill name, mode chosen, paths.
- Invocation: `/<name> [args]`.
- **Project team-shared**: remind the user to commit and open a PR so the team can review.
- **Project personal**: note that it lives in this working tree only — it won't sync to other machines or worktrees unless the user adds it to their dotfiles.
- **Global personal**: it's available across all projects right away.

Claude Code's live change detection picks the new skill up within the current session.
