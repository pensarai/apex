import { z } from "zod";

export const FINDING_TYPES = [
  "vulnerability",
  "informational",
  "expected-behavior",
] as const;

export type FindingType = (typeof FINDING_TYPES)[number];

export interface FindingJudgeInput {
  /** The full POC script content */
  pocScript: string;
  /** Script language */
  pocType: "bash" | "python" | "javascript";
  /** Relative path to the persisted POC file, when available */
  pocPath?: string;
  /** Target URL/host being assessed */
  target?: string;
  /** POC execution output */
  pocOutput: {
    stdout: string;
    stderr: string;
    exitCode: number;
  };
  /** The vulnerability claim to validate against */
  claim: {
    title: string;
    description: string;
    impact: string;
    evidence: string;
    endpoint: string;
    vulnerabilityClass?: string;
  };
}

export interface FindingJudgeVerificationDetails {
  /** Concrete actions the judge took before deciding */
  verificationSteps?: string[];
  /** Specific observations from tools or provided artifacts */
  toolEvidence?: string[];
  /** Whether the judge independently reran or otherwise reproduced the POC */
  reproducedPoc?: boolean;
  /** Whether public web research influenced the decision */
  webResearchUsed?: boolean;
  /** Known gaps in verification */
  limitations?: string[];
}

export interface FindingJudgeResult extends FindingJudgeVerificationDetails {
  /** Whether the finding is legitimate and well-demonstrated */
  valid: boolean;
  /** Classification of the finding */
  findingType: FindingType;
  /** Confidence in the judgment (0.0-1.0) */
  confidence: number;
  /** Explanation of the judgment */
  reasoning: string;
  /** Specific concerns identified (empty if valid) */
  concerns: string[];
  /** Present when the judge fell back due to an error — contains diagnostics */
  error?: {
    message: string;
    type: string;
    model: string;
    stack?: string;
  };
}

export const FindingJudgeOutputSchema = z.object({
  valid: z
    .boolean()
    .describe(
      "Whether the POC legitimately demonstrates the claimed vulnerability",
    ),
  findingType: z
    .enum(FINDING_TYPES)
    .describe(
      "Classification: 'vulnerability' for genuine security issues, 'informational' for low-risk observations worth noting, 'expected-behavior' for findings that describe intentional design decisions",
    ),
  confidence: z
    .number()
    .min(0)
    .max(1)
    .describe(
      "Confidence in the judgment, a decimal between 0.0 (no confidence) and 1.0 (certain)",
    ),
  reasoning: z
    .string()
    .describe(
      "Brief explanation of the key tool observations and analysis that led to this judgment",
    ),
  concerns: z
    .array(z.string())
    .describe(
      "Specific concerns identified. Empty array only when the finding is valid and high-confidence.",
    ),
  verificationSteps: z
    .array(z.string())
    .describe("Concrete verification actions performed before deciding."),
  toolEvidence: z
    .array(z.string())
    .describe("Specific observations from tool output or provided artifacts."),
  reproducedPoc: z
    .boolean()
    .describe("Whether the judge reran or independently reproduced the POC."),
  webResearchUsed: z
    .boolean()
    .describe("Whether web_search/get_page materially informed the judgment."),
  limitations: z
    .array(z.string())
    .describe("Remaining verification gaps or environmental limitations."),
});

export type FindingJudgeAgentOutput = z.infer<typeof FindingJudgeOutputSchema>;
