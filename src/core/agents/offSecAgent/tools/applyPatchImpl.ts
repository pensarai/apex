import {
  assertWorkspaceFileAbsent,
  deleteWorkspaceFile,
  readWorkspaceFile,
  resolveFilePath,
  validateWorkspaceFileContent,
  writeWorkspaceFile,
} from "./fileWorkspace";
import {
  applyFileDiff,
  type EolAdaptation,
  PatchApplyError,
} from "./patchApply";
import { type ParsedFileDiff, parseUnifiedDiff } from "./patchParse";
import type { ToolContext } from "./types";

export { parseUnifiedDiff } from "./patchParse";

export type FilePatchStatus = "applied" | "failed" | "unapplied";

export type FilePatchResult = {
  path: string;
  /** Back-compat alias: true exactly when status is "applied". */
  success: boolean;
  status: FilePatchStatus;
  error?: string;
  /** Hunks committed for this file; only set when status is "applied". */
  hunksApplied?: number;
  created?: boolean;
  deleted?: boolean;
  /** Set when line endings were adapted to the target file (LF patch on a CRLF file or vice versa). */
  eolAdaptation?: Exclude<EolAdaptation, "none">;
};

export type ApplyPatchResult = {
  success: boolean;
  error: string;
  files: FilePatchResult[];
};

type PlannedFile = {
  diff: ParsedFileDiff;
  displayPath: string;
  targetPath: string;
  kind: "create" | "edit" | "delete";
  /** Content read during preflight; the commit's conditional baseline. */
  original?: string;
  next: string;
  eolAdaptation: EolAdaptation;
};
function describeError(err: unknown): string {
  if (err instanceof PatchApplyError) {
    const where = err.hunkIndex >= 0 ? `hunk ${err.hunkIndex + 1}: ` : "";
    return `${where}${err.message}`;
  }
  return err instanceof Error ? err.message : String(err);
}

// Windows filesystems fold case, so patch entries differing only by case
// are the same target; detect duplicates under the same rule the mutation
// helpers use for lock keys.
export function duplicateTargetKey(
  ctx: ToolContext,
  targetPath: string,
): string {
  const isWindows = ctx.sandbox
    ? ctx.sandbox.type === "windows"
    : process.platform === "win32";
  return isWindows ? targetPath.toLowerCase() : targetPath;
}

function receipt(
  plan: PlannedFile,
  status: FilePatchStatus,
  error?: string,
): FilePatchResult {
  const result: FilePatchResult = {
    path: plan.displayPath,
    success: status === "applied",
    status,
  };
  if (error !== undefined) result.error = error;
  if (status === "applied") {
    result.hunksApplied = plan.diff.hunks.length;
    result.created = plan.kind === "create";
    result.deleted = plan.kind === "delete";
    if (plan.eolAdaptation !== "none") {
      result.eolAdaptation = plan.eolAdaptation;
    }
  }
  return result;
}

/**
 * Validate one file diff against current workspace state without mutating
 * anything. Create targets are asserted absent and every prepared output is
 * checked against the shared text/size limits here, so a predictable failure
 * never follows an already-committed file.
 */
async function preflightFile(
  ctx: ToolContext,
  diff: ParsedFileDiff,
): Promise<PlannedFile> {
  const displayPath = diff.newPath || diff.oldPath;
  const inputPath = diff.isDelete ? diff.oldPath : diff.newPath || diff.oldPath;
  const targetPath = await resolveFilePath(ctx, inputPath, {
    confineToCwd: true,
    followFinal: !diff.isDelete,
  });

  if (diff.isDelete) {
    const contentPath = await resolveFilePath(ctx, targetPath, {
      confineToCwd: true,
    });
    if (
      duplicateTargetKey(ctx, contentPath) !==
      duplicateTargetKey(ctx, targetPath)
    ) {
      throw new Error("Deletion patches require a regular file, not a symlink");
    }
    const original = await readWorkspaceFile(ctx, targetPath);
    applyFileDiff(original, diff);
    return {
      diff,
      displayPath,
      targetPath,
      kind: "delete",
      original,
      next: "",
      eolAdaptation: "none",
    };
  }

  if (diff.isNew) {
    await assertWorkspaceFileAbsent(ctx, targetPath);
    const applied = applyFileDiff("", diff);
    validateWorkspaceFileContent(applied.content);
    return {
      diff,
      displayPath,
      targetPath,
      kind: "create",
      next: applied.content,
      eolAdaptation: applied.eolAdaptation,
    };
  }

  const original = await readWorkspaceFile(ctx, targetPath);
  const applied = applyFileDiff(original, diff);
  validateWorkspaceFileContent(applied.content);
  return {
    diff,
    displayPath,
    targetPath,
    kind: "edit",
    original,
    next: applied.content,
    eolAdaptation: applied.eolAdaptation,
  };
}

export async function applyPatchImpl(
  ctx: ToolContext,
  diffText: string,
): Promise<ApplyPatchResult> {
  let diffs: ParsedFileDiff[];
  try {
    diffs = parseUnifiedDiff(diffText);
  } catch (err: unknown) {
    return {
      success: false,
      error: describeError(err),
      files: [],
    };
  }

  // Preflight every file before mutating anything.
  const plans: PlannedFile[] = [];
  const targets = new Set<string>();
  for (const diff of diffs) {
    let plan: PlannedFile;
    try {
      plan = await preflightFile(ctx, diff);
    } catch (err: unknown) {
      const message = describeError(err);
      const displayPath = diff.newPath || diff.oldPath;
      const unappliedFor = (later: ParsedFileDiff): PlannedFile => ({
        diff: later,
        displayPath: later.newPath || later.oldPath,
        targetPath: "",
        kind: later.isNew ? "create" : later.isDelete ? "delete" : "edit",
        next: "",
        eolAdaptation: "none",
      });
      if (ctx.abortSignal?.aborted) {
        return {
          success: false,
          error:
            "Patch application aborted during preflight; no files were changed",
          files: [
            ...plans.map((p) => receipt(p, "unapplied")),
            receipt(unappliedFor(diff), "unapplied", "Aborted"),
            ...diffs
              .slice(plans.length + 1)
              .map((later) => receipt(unappliedFor(later), "unapplied")),
          ],
        };
      }
      const files = [
        ...plans.map((p) => receipt(p, "unapplied")),
        receipt(unappliedFor(diff), "failed", message),
        ...diffs
          .slice(plans.length + 1)
          .map((later) => receipt(unappliedFor(later), "unapplied")),
      ];
      return {
        success: false,
        error: `Failed applying patch to ${displayPath}: ${message}`,
        files,
      };
    }
    if (targets.has(duplicateTargetKey(ctx, plan.targetPath))) {
      const message = `Patch targets the same file twice: ${plan.displayPath}`;
      return {
        success: false,
        error: message,
        files: [
          ...plans.map((p) => receipt(p, "unapplied")),
          receipt(plan, "failed", message),
          ...diffs.slice(plans.length + 1).map((later) =>
            receipt(
              {
                diff: later,
                displayPath: later.newPath || later.oldPath,
                targetPath: "",
                kind: later.isNew
                  ? "create"
                  : later.isDelete
                    ? "delete"
                    : "edit",
                next: "",
                eolAdaptation: "none",
              },
              "unapplied",
            ),
          ),
        ],
      };
    }
    targets.add(duplicateTargetKey(ctx, plan.targetPath));
    plans.push(plan);
  }

  // Commit: every write is conditional on the preflight read, so a file
  // changed in between fails loudly instead of clobbering.
  const files: FilePatchResult[] = [];
  let aborted = false;
  for (const plan of plans) {
    if (ctx.abortSignal?.aborted) {
      aborted = true;
      files.push(receipt(plan, "unapplied", "Aborted before commit"));
      continue;
    }
    try {
      if (plan.kind === "delete") {
        await deleteWorkspaceFile(ctx, plan.targetPath, {
          expected: plan.original,
        });
      } else if (plan.kind === "create") {
        await writeWorkspaceFile(ctx, plan.targetPath, plan.next, {
          expected: null,
        });
      } else {
        await writeWorkspaceFile(ctx, plan.targetPath, plan.next, {
          expected: plan.original,
        });
      }
      files.push(receipt(plan, "applied"));
    } catch (err: unknown) {
      const message = describeError(err);
      files.push(receipt(plan, "failed", message));
      for (const remaining of plans.slice(files.length)) {
        files.push(receipt(remaining, "unapplied"));
      }
      return {
        success: false,
        error: `Failed applying patch to ${plan.displayPath}: ${message} (earlier files remain applied; no rollback)`,
        files,
      };
    }
  }

  return {
    success: !aborted,
    error: aborted
      ? "Patch application aborted after preflight; files not committed are marked unapplied"
      : "",
    files,
  };
}
