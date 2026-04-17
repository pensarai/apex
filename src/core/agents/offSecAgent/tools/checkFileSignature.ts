import { tool } from "ai";
import { z } from "zod";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import type { ToolContext } from "./types";

/**
 * Hardcoded signature table used for MVP malware-class detection.
 *
 * Keyed by SHA-256 (lowercase). Value is the human-readable signature
 * name — it appears verbatim in the detection event's `summary` field so
 * user-authored assertion regexes (e.g. `/eicar/i`) can match directly.
 *
 * This list is deliberately small and well-known. For richer coverage the
 * tool can be swapped to invoke YARA / ClamAV in-sandbox without changing
 * the tool's agent-facing contract.
 */
const KNOWN_BAD_HASHES: Record<string, string> = {
  // EICAR Standard Anti-Virus Test File — the canonical "malware" that
  // every AV engine is expected to catch. Safe: it's just a 68-byte ASCII
  // string crafted to trigger signatures without any actual payload.
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f":
    "EICAR-STD-ANTIVIRUS-TEST-FILE",
  // Sha256 of the EICAR test string wrapped in common containers
  "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267":
    "EICAR-TEST-FILE-COMPRESSED",
  // AMTSO "test virus" alternates (publicly documented test artifacts)
  "74d6c34a42ef1f4a33f7dc5d90e09f2c08dca86a02f89f1b7bd0ad44d23b4a6a":
    "AMTSO-WICAR-TEST",
};

export const checkFileSignatureInputSchema = z.object({
  filePath: z
    .string()
    .describe(
      "Absolute path to the file to hash & signature-match. For sandbox-staged artifacts this is typically /work/artifact.* or a path inside the extraction directory.",
    ),
  computeHashes: z
    .array(z.enum(["sha256", "sha1", "md5"]))
    .optional()
    .describe(
      "Hash algorithms to compute (default: sha256 only). sha1/md5 are returned for reporting but only sha256 is used for signature matching.",
    ),
  toolCallDescription: z
    .string()
    .describe(
      "A concise, human-readable description of what this tool call is doing (e.g., 'Hashing extracted zip member to verify EICAR presence')",
    ),
});

export type CheckFileSignatureInput = z.infer<
  typeof checkFileSignatureInputSchema
>;

export type CheckFileSignatureResult = {
  success: boolean;
  filePath: string;
  hashes: Partial<Record<"sha256" | "sha1" | "md5", string>>;
  matches: Array<{ signature: string; hash: string; algorithm: "sha256" }>;
  error?: string;
};

async function hashInSandbox(
  ctx: ToolContext,
  path: string,
  algos: Array<"sha256" | "sha1" | "md5">,
): Promise<CheckFileSignatureResult["hashes"]> {
  if (!ctx.sandbox) {
    throw new Error("hashInSandbox called without sandbox");
  }
  const out: CheckFileSignatureResult["hashes"] = {};
  for (const algo of algos) {
    const bin =
      algo === "sha256"
        ? "sha256sum"
        : algo === "sha1"
          ? "sha1sum"
          : "md5sum";
    const result = await ctx.sandbox.execute(`${bin} '${path.replace(/'/g, "'\\''")}' 2>&1`, {
      timeout: 30,
    });
    if (!result.success || result.exitCode !== 0) {
      throw new Error(
        `${bin} failed (exit ${result.exitCode}): ${result.stderr || result.stdout}`,
      );
    }
    const firstWord = result.stdout.trim().split(/\s+/)[0];
    if (!firstWord || !/^[0-9a-f]+$/i.test(firstWord)) {
      throw new Error(`${bin} produced unexpected output: ${result.stdout}`);
    }
    out[algo] = firstWord.toLowerCase();
  }
  return out;
}

function hashLocally(
  path: string,
  algos: Array<"sha256" | "sha1" | "md5">,
): CheckFileSignatureResult["hashes"] {
  const bytes = readFileSync(path);
  const out: CheckFileSignatureResult["hashes"] = {};
  for (const algo of algos) {
    out[algo] = createHash(algo).update(bytes).digest("hex");
  }
  return out;
}

/**
 * Hash-based signature match. Ground-truth bytes-on-disk are hashed and
 * compared against a curated table of known-bad SHA-256 values. On match
 * a `signature_match` detection event is emitted with the signature name
 * literally in the summary (so user regex assertions can target it).
 */
export function checkFileSignature(ctx: ToolContext) {
  return tool({
    description: `Compute cryptographic hashes of a file and match against a curated table of known-bad SHA-256 signatures.

Use this when the scenario calls for confirming a file truly contains a
known-malicious or test-virus sample (EICAR, signature-test artifacts). On
match, emits a \`signature_match\` detection event — you do NOT need to
call \`emit_detection_event\` separately.

Current signature table is hardcoded and small (EICAR + canonical AV test
strings). Unknown-but-suspicious files will hash cleanly and return
\`matches: []\` — that is a valid honest result; do not manufacture a
signature_match event for them.

Returns hashes you can inspect for follow-up tooling or logging. Runs
through the sandbox when available; otherwise reads the file locally.`,
    inputSchema: checkFileSignatureInputSchema,
    execute: async (input): Promise<CheckFileSignatureResult> => {
      const algos = input.computeHashes ?? ["sha256"];
      try {
        const hashes = ctx.sandbox
          ? await hashInSandbox(ctx, input.filePath, algos)
          : hashLocally(input.filePath, algos);

        const sha256 = hashes.sha256;
        const matches: CheckFileSignatureResult["matches"] = [];
        if (sha256 && KNOWN_BAD_HASHES[sha256]) {
          const signature = KNOWN_BAD_HASHES[sha256];
          matches.push({ signature, hash: sha256, algorithm: "sha256" });
          ctx.eventBus?.emit("detection_event", {
            kind: "signature_match",
            severity: "high",
            source: "apex",
            summary: `signature_match: ${signature} in ${input.filePath}`,
            data: {
              signature,
              hash: sha256,
              algorithm: "sha256",
              filePath: input.filePath,
              matchedRuleSource: "KNOWN_BAD_HASHES (curated)",
            },
          });
        }

        return {
          success: true,
          filePath: input.filePath,
          hashes,
          matches,
        };
      } catch (error) {
        return {
          success: false,
          filePath: input.filePath,
          hashes: {},
          matches: [],
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

/** Exported for tests and for extending the signature table externally. */
export { KNOWN_BAD_HASHES };
