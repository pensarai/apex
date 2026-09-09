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

const SourceTraceSchema = z.object({
  source: SourceLocationSchema.optional(),
  sink: SourceLocationSchema.optional(),
  path: z.array(SourceLocationSchema).optional(),
  notes: z.string().optional(),
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
      sourceTrace: SourceTraceSchema.optional(),
      artifacts: z.array(ArtifactSchema).optional(),
      toolCallDescription: z
        .string()
        .optional()
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

State machine: hypothesis -> investigating -> repro_attempted -> confirmed (requires verification.status=succeeded), or rejected/deferred from earlier states. Transitions to investigating or repro_attempted require artifact references and/or a substantive sourceTrace.`,
    inputSchema: z.object({
      id: z.string(),
      state: CandidateStateSchema.optional(),
      confidence: z.enum(["low", "medium", "high"]).optional(),
      summary: z.string().optional(),
      artifacts: z.array(ArtifactSchema).optional(),
      sourceTrace: SourceTraceSchema.optional(),
      verification: z
        .object({
          strategy: z.string(),
          status: z.enum(["not_started", "running", "failed", "succeeded"]),
          notes: z.string().optional(),
        })
        .optional(),
      toolCallDescription: z
        .string()
        .optional()
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
          sourceTrace: input.sourceTrace,
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
            "Follow the state machine; investigating/repro_attempted need artifacts or sourceTrace; confirmed needs repro_attempted plus verification.status=succeeded.",
        };
      }
    },
  });
}

export function listWhiteboxCandidates(ctx: ToolContext) {
  return tool({
    description:
      "List whitebox vulnerability candidates for this session (capped). Returns state, confidence, traces, and artifact references.",
    inputSchema: z.object({
      state: CandidateStateSchema.optional(),
      limit: z
        .number()
        .int()
        .min(1)
        .max(200)
        .optional()
        .describe("Max candidates to return (default 50, max 200)"),
      toolCallDescription: z
        .string()
        .optional()
        .describe("A concise description of the candidate listing"),
    }),
    execute: async ({ state, limit }) => {
      const effectiveLimit = limit ?? 50;
      const { candidates, total } = await listCandidates(ctx.session, {
        state,
        limit: effectiveLimit,
      });
      const truncated = candidates.length < total;
      return {
        success: true,
        summary: truncated
          ? `Showing ${candidates.length} of ${total} whitebox candidate(s).`
          : `Found ${candidates.length} whitebox candidate(s).`,
        data: { candidates, total },
        artifactPaths: candidates.flatMap((candidate) =>
          candidate.artifacts.map((artifact) => artifact.path),
        ),
        nextActions: [
          "Prioritize high-confidence investigating/repro_attempted candidates.",
          "Reject or defer stale hypotheses so they do not pollute the engagement.",
        ],
        truncated,
      };
    },
  });
}
