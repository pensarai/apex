import { tool } from "ai";
import { z } from "zod";
import {
  createWhiteboxCandidate as createCandidate,
  listWhiteboxCandidates as listCandidates,
  updateWhiteboxCandidate as updateCandidate,
} from "../../../whitebox";
import type { ToolContext } from "./types";

const ArtifactSchema = z.object({
  path: z.string(),
  type: z.enum([
    "repo-profile",
    "static-scan",
    "code-query",
    "source-trace",
    "candidate",
    "job-log",
    "fuzz-harness",
    "fuzz-crash",
    "build-log",
    "raw-output",
  ]),
  description: z.string(),
});

const SourceLocationSchema = z.object({
  file: z.string(),
  line: z.number().optional(),
  symbol: z.string().optional(),
});

const CandidateStateSchema = z.enum([
  "hypothesis",
  "investigating",
  "repro_attempted",
  "confirmed",
  "rejected",
  "deferred",
]);

export function createWhiteboxCandidate(ctx: ToolContext) {
  return tool({
    description: `Create a whitebox vulnerability candidate.

Use this for plausible source-code findings that are not yet confirmed enough
for document_vulnerability. Candidates keep hypotheses, source-to-sink traces,
scanner artifacts, fuzzing logs, and verification status out of official findings.`,
    inputSchema: z.object({
      title: z.string(),
      vulnerabilityClass: z.string(),
      summary: z.string(),
      confidence: z.enum(["low", "medium", "high"]),
      sourceTrace: z
        .object({
          source: SourceLocationSchema.optional(),
          sink: SourceLocationSchema.optional(),
          path: z.array(SourceLocationSchema).optional(),
          notes: z.string().optional(),
        })
        .optional(),
      artifacts: z.array(ArtifactSchema).optional(),
      toolCallDescription: z
        .string()
        .describe("A concise description of the candidate being created"),
    }),
    execute: async (input) => {
      const candidate = await createCandidate({
        session: ctx.session,
        title: input.title,
        vulnerabilityClass: input.vulnerabilityClass,
        summary: input.summary,
        confidence: input.confidence,
        sourceTrace: input.sourceTrace,
        artifacts: input.artifacts,
      });
      return {
        success: true,
        summary: `Created whitebox candidate ${candidate.id}: ${candidate.title}`,
        data: { candidate },
        artifactPaths: candidate.artifacts.map((artifact) => artifact.path),
        nextActions: [
          "Move candidate to investigating after reading source context.",
          "Attempt a reproducer or dynamic verification before document_vulnerability.",
        ],
        truncated: false,
      };
    },
  });
}

export function updateWhiteboxCandidate(ctx: ToolContext) {
  return tool({
    description: `Update a whitebox candidate state, evidence, or verification status.

Allowed state flow: hypothesis -> investigating -> repro_attempted -> confirmed,
rejected, or deferred. State transitions after hypothesis require artifact or
source-trace evidence references.`,
    inputSchema: z.object({
      id: z.string(),
      state: CandidateStateSchema.optional(),
      confidence: z.enum(["low", "medium", "high"]).optional(),
      summary: z.string().optional(),
      artifacts: z.array(ArtifactSchema).optional(),
      verification: z
        .object({
          strategy: z.string(),
          status: z.enum(["not_started", "running", "failed", "succeeded"]),
          notes: z.string().optional(),
        })
        .optional(),
      toolCallDescription: z
        .string()
        .describe("A concise description of the candidate update"),
    }),
    execute: async (input) => {
      try {
        const candidate = await updateCandidate({
          session: ctx.session,
          id: input.id,
          state: input.state,
          confidence: input.confidence,
          summary: input.summary,
          artifacts: input.artifacts,
          verification: input.verification,
        });
        return {
          success: true,
          summary: `Updated whitebox candidate ${candidate.id}: ${candidate.state}`,
          data: { candidate },
          artifactPaths: candidate.artifacts.map((artifact) => artifact.path),
          nextActions:
            candidate.state === "confirmed"
              ? [
                  "Use document_vulnerability only if the proof demonstrates exploitability.",
                ]
              : [
                  "Continue tracing or verification based on the candidate state.",
                ],
          truncated: false,
        };
      } catch (error) {
        return {
          success: false,
          summary: `Failed to update candidate: ${error instanceof Error ? error.message : String(error)}`,
          artifactPaths: [],
          nextActions: ["List candidates and retry with a valid id/evidence."],
          recovery:
            "Transitions after hypothesis need artifact references from scans, code queries, source traces, jobs, or repro outputs.",
        };
      }
    },
  });
}

export function listWhiteboxCandidates(ctx: ToolContext) {
  return tool({
    description:
      "List whitebox vulnerability candidates for this session, including state, confidence, source traces, and artifact references.",
    inputSchema: z.object({
      state: CandidateStateSchema.optional(),
      toolCallDescription: z
        .string()
        .describe("A concise description of the candidate listing"),
    }),
    execute: async ({ state }) => {
      const candidates = (await listCandidates(ctx.session)).filter(
        (candidate) => !state || candidate.state === state,
      );
      return {
        success: true,
        summary: `Found ${candidates.length} whitebox candidate(s).`,
        data: { candidates },
        artifactPaths: candidates.flatMap((candidate) =>
          candidate.artifacts.map((artifact) => artifact.path),
        ),
        nextActions: [
          "Prioritize high-confidence investigating/repro_attempted candidates.",
          "Reject or defer stale hypotheses so they do not pollute the engagement.",
        ],
        truncated: false,
      };
    },
  });
}
