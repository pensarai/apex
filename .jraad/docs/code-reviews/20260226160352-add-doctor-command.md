# Code Review: Add doctor command

| Field       | Value |
|-------------|-------|
| **Date**    | 2026-02-26 16:03:52 UTC |
| **Target**  | PR #194 |
| **Base**    | `canary` |
| **Mode**    | default |
| **Commits** | 2 commits |
| **Files**   | 3 files changed |

---

## Summary Verdict

A useful addition that follows a well-established CLI pattern (`brew doctor`, `flutter doctor`). The implementation is clean and the UX is thoughtful — version display, API key overview, interactive install prompt. Two things to address: the `toolExists` function is duplicated verbatim from `src/core/agents/specialized/utils.ts`, and `detectPackageManager` hardcodes `nmap` despite being named generically, which works against the stated goal of extensibility. Neither blocks shipping, but the duplication in particular should be cleaned up soon.

---

## Findings

### Recommendations

**1. `toolExists` is duplicated from `src/core/agents/specialized/utils.ts`** — Should fix, fast follow-up

- **Location**: `src/core/doctor.ts:4-22` and `src/core/agents/specialized/utils.ts:49-68`
- **What**: The `toolExists` function in `doctor.ts` is a verbatim copy of the one in `utils.ts`. Same logic, same fallback from `command -v` to `which`, same error handling.
- **Why it matters**: Two copies means two places to maintain. If someone fixes a bug or adds Windows support to one, the other stays broken. This is the kind of duplication that quietly rots.
- **Suggestion**: Extract `toolExists` to a shared module (e.g., `src/core/utils/system.ts` or similar) and import it in both places.
- **Timing**: Fast follow-up. The duplication is low-risk right now since both copies are identical, but it should be resolved before either is modified.

**2. `detectPackageManager` hardcodes `nmap`** — Should fix, fast follow-up

- **Location**: `src/core/doctor.ts:24-44`
- **What**: The function is named generically but every return value hardcodes `nmap` in the install command string. The PR description explicitly says "Can be extended to support other tools we want to sidecar in the future."
- **Why it matters**: When the next tool is added, this function either gets duplicated or rewritten. A small change now makes future additions trivial.
- **Suggestion**: Accept a `packageName: string` parameter and interpolate it into the install commands:

```typescript
function detectPackageManager(packageName: string): { name: string; installCmd: string } | null {
  const platform = process.platform;
  if (platform === "darwin" && toolExists("brew")) {
    return { name: "Homebrew", installCmd: `brew install ${packageName}` };
  }
  // ... etc
}
```

- **Timing**: Fast follow-up. The current code works for nmap. Making it generic is a 5-minute change that pays off as soon as a second tool is added.

**3. No Windows support — and the old README instructions were removed** — Should fix, block this PR

- **Location**: `src/core/doctor.ts:4-22` (toolExists), `src/core/doctor.ts:24-44` (detectPackageManager), `README.md`
- **What**: `toolExists` uses `command -v` and `which`, both Unix-only. `detectPackageManager` doesn't handle `choco`, `winget`, or `scoop`. Meanwhile, the README diff removes the Windows install instructions ("Download installer from https://nmap.org/download.html and ensure nmap is on your PATH") and replaces them with "run `pensar doctor`" — which won't help Windows users install nmap.
- **Why it matters**: Windows users who previously had clear instructions now get pointed to a command that can't detect or install nmap on their platform. The doctor command will silently report "No supported package manager found" with a link to nmap.org, which is less helpful than what the README used to say.
- **Suggestion**: At minimum, add a `where` fallback for Windows in `toolExists` and handle `choco`/`winget`/`scoop` in `detectPackageManager`. Alternatively, if Windows support isn't a priority right now, keep the Windows-specific instructions in the README alongside the `pensar doctor` recommendation.
- **Timing**: Block this PR. The regression in Windows documentation is concrete. Either restore the Windows instructions in the README or add basic Windows support to the doctor command.

**4. AWS IAM check is incomplete** — Should fix, fast follow-up

- **Location**: `src/core/doctor.ts:64`
- **What**: The doctor checks for `AWS_ACCESS_KEY_ID` but not `AWS_SECRET_ACCESS_KEY`. These are always used together — having one without the other is a misconfiguration, not a success. The README documents both (plus `AWS_SESSION_TOKEN` and `AWS_REGION`) as needed for Bedrock IAM auth. The actual AI utils code (`src/core/ai/utils.ts:48-52`) checks for all four.
- **Why it matters**: A user who sets only `AWS_ACCESS_KEY_ID` would see a green checkmark for "AWS IAM" and then get auth failures at runtime. The doctor command should help catch exactly this kind of partial configuration.
- **Suggestion**: Either check that both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are set, or show a warning when only one is present. Consider also checking `AWS_REGION` since it's required for Bedrock.
- **Timing**: Fast follow-up. The current behavior is misleading but not dangerous — users would discover the issue quickly at runtime.

### Suggestions

**5. Consider a tool definition pattern for extensibility**

- **Location**: `src/core/doctor.ts:78-155`
- **What**: The nmap check, version display, and install prompt are all inline in `runDoctor`. If you're planning to add more tools, a declarative approach would scale better:

```typescript
interface ToolCheck {
  name: string;
  description: string;
  versionCmd?: string;
  required: boolean;
}

const TOOLS: ToolCheck[] = [
  { name: "nmap", description: "network scanning", versionCmd: "nmap --version", required: false },
];
```

- **Why it matters**: Each new tool would be a single object in an array rather than another block of if/else logic in `runDoctor`. This is the kind of structure that makes the PR description's "can be extended" claim actually true.
- **Timing**: Not blocking. Worth considering when the second tool is added.

**6. `prompt` writes to stderr**

- **Location**: `src/core/doctor.ts:48-49`
- **What**: The readline interface uses `output: process.stderr`. The prompt text ("Install nmap via Homebrew? [y/N]") goes to stderr instead of stdout.
- **Why it matters**: This is likely intentional to keep stdout clean for piping, which is a reasonable convention. But it means the prompt text won't appear if stderr is redirected, which could confuse users in some terminal setups. If keeping stdout clean is the goal, that's fine — just wanted to flag it as a conscious choice.

### Nits

**7. Help text alignment**

- **Location**: `src/cli.ts:58-60`
- **What**: The `doctor` help line uses fewer spaces than the others for alignment. Compare:

```
  pensar targeted-pentest [options]   Run a targeted pentest...
  pensar doctor                      Check dependencies...
```

The `doctor` line has 22 spaces of padding vs. the 3-space gap used elsewhere. It's close but slightly off from the other entries.

### Praise

- The overall UX is well thought out. Showing tool versions, API key status with clear icons (✓/✗/·), and offering an interactive install prompt is exactly what a good doctor command should do.
- Using `spawnSync` with `stdio: "inherit"` for the install step is the right call — it lets users see install progress and enter passwords for `sudo`.
- The dynamic import in `cli.ts` (`await import("./core/doctor")`) keeps the doctor module out of the main bundle for users who never run it.

---

## Questions for the Author

1. **Is Windows a supported platform?** The old README had explicit Windows instructions that this PR removes. If Windows users are part of the audience, the doctor command needs `where` support and the README should retain or replace those instructions.
2. **Are there other tools planned for the doctor check?** The PR description mentions extensibility. If there are concrete plans (e.g., `gobuster`, `sqlmap` — tools already checked in `src/core/agents/specialized/utils.ts`), it might be worth setting up the extensible pattern now rather than retrofitting it.
3. **Should the doctor command share logic with `detectEnvironment` in `utils.ts`?** That function already checks for nmap and 13 other tools. There may be an opportunity to unify the tool-checking logic between the agent environment detection and the doctor command.
