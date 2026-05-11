import { appendFileSync } from "fs";
import { describe, expect, it } from "vitest";

import { judgeFinding, type FindingType } from "./index";
import type { AIModel } from "../../../ai";
import { getModelInfo } from "../../../ai/models";
import {
  judgeEvalCases,
  type JudgeEvalCase,
  type JudgeEvalCategory,
} from "./evals/cases";

const RUN_EVALS = process.env.RUN_FINDING_JUDGE_EVALS === "1";
const EVAL_MODEL = (process.env.FINDING_JUDGE_EVAL_MODEL ||
  "claude-haiku-4-5") as AIModel;
const CONFIDENTLY_WRONG_THRESHOLD = 0.8;
const TRUE_POSITIVE_TARGET = 0.95;
const FALSE_POSITIVE_REJECTION_TARGET = 0.9;
const EVAL_TIMEOUT_MS = 30 * 60 * 1000;

interface EvalRecord {
  testCase: JudgeEvalCase;
  actual: {
    valid: boolean;
    findingType: FindingType;
    confidence: number;
    reasoning: string;
    concerns: string[];
    error?: unknown;
  };
  passed: boolean;
  labelPassed: boolean;
  confidencePassed: boolean;
  concernsPassed: boolean;
}

interface CategorySummary {
  total: number;
  passed: number;
  labelPassed: number;
  confidencePassed: number;
  concernsPassed: number;
  predicted: number;
  truePositive: number;
}

function credentialSkipReason(model: AIModel): string | undefined {
  const provider = getModelInfo(model).provider;

  switch (provider) {
    case "anthropic":
      return process.env.ANTHROPIC_API_KEY
        ? undefined
        : "ANTHROPIC_API_KEY is required";
    case "openai":
      return process.env.OPENAI_API_KEY
        ? undefined
        : "OPENAI_API_KEY is required";
    case "google":
      return process.env.GOOGLE_GENERATIVE_AI_API_KEY
        ? undefined
        : "GOOGLE_GENERATIVE_AI_API_KEY is required";
    case "openrouter":
      return process.env.OPENROUTER_API_KEY
        ? undefined
        : "OPENROUTER_API_KEY is required";
    case "bedrock":
      return process.env.BEDROCK_API_KEY ||
        (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY)
        ? undefined
        : "BEDROCK_API_KEY or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY is required";
    case "pensar":
      return process.env.PENSAR_API_KEY
        ? undefined
        : "PENSAR_API_KEY is required";
    case "inception":
      return process.env.INCEPTION_API_KEY
        ? undefined
        : "INCEPTION_API_KEY is required";
    case "local":
      return undefined;
    default:
      return `Unsupported provider for model ${model}`;
  }
}

const skipReason = !RUN_EVALS
  ? "RUN_FINDING_JUDGE_EVALS=1 is required"
  : credentialSkipReason(EVAL_MODEL);

if (skipReason) {
  console.warn(`[FindingJudgeEval] Skipping evals: ${skipReason}`);
}

const describeIfEnabled = skipReason ? describe.skip : describe;

function textMatches(result: EvalRecord["actual"], needle: string): boolean {
  const haystack = [result.reasoning, ...result.concerns]
    .join("\n")
    .toLowerCase();
  return haystack.includes(needle.toLowerCase());
}

function evaluateRecord(testCase: JudgeEvalCase, actual: EvalRecord["actual"]) {
  const { expected } = testCase;
  const labelPassed =
    actual.valid === expected.valid &&
    actual.findingType === expected.findingType &&
    actual.error == null;
  const confidencePassed =
    (expected.minConfidence == null ||
      actual.confidence >= expected.minConfidence) &&
    (expected.maxConfidence == null ||
      actual.confidence <= expected.maxConfidence);
  const concernsPassed =
    expected.mustMentionConcerns?.every((concern) =>
      textMatches(actual, concern),
    ) ?? true;

  return {
    labelPassed,
    confidencePassed,
    concernsPassed,
    passed: labelPassed && confidencePassed && concernsPassed,
  };
}

function predictedCategory(actual: EvalRecord["actual"]): JudgeEvalCategory {
  if (!actual.valid) return "false-positive";
  if (actual.findingType === "expected-behavior") return "expected-behavior";
  if (actual.findingType === "informational") return "informational";
  return "true-positive";
}

function buildCategorySummaries(records: EvalRecord[]) {
  const summaries = new Map<JudgeEvalCategory, CategorySummary>();

  for (const record of records) {
    const category = record.testCase.category;
    const summary =
      summaries.get(category) ??
      ({
        total: 0,
        passed: 0,
        labelPassed: 0,
        confidencePassed: 0,
        concernsPassed: 0,
        predicted: 0,
        truePositive: 0,
      } satisfies CategorySummary);

    summary.total += 1;
    if (record.passed) summary.passed += 1;
    if (record.labelPassed) summary.labelPassed += 1;
    if (record.confidencePassed) summary.confidencePassed += 1;
    if (record.concernsPassed) summary.concernsPassed += 1;

    summaries.set(category, summary);
  }

  for (const record of records) {
    const predicted = predictedCategory(record.actual);
    const summary = summaries.get(predicted);
    if (!summary) continue;

    summary.predicted += 1;
    if (predicted === record.testCase.category) {
      summary.truePositive += 1;
    }
  }

  return summaries;
}

function percent(numerator: number, denominator: number): string {
  if (denominator === 0) return "n/a";
  return `${((numerator / denominator) * 100).toFixed(1)}%`;
}

function buildSummaryMarkdown(records: EvalRecord[]): string {
  const summaries = buildCategorySummaries(records);
  const lines = [
    "## Finding Judge Eval Summary",
    "",
    `Model: \`${EVAL_MODEL}\``,
    "",
    "| Category | Passed | Precision | Recall | Label Accuracy | Confidence Accuracy | Concern Accuracy |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
  ];

  for (const [category, summary] of summaries) {
    lines.push(
      `| ${category} | ${summary.passed}/${summary.total} (${percent(summary.passed, summary.total)}) | ${percent(summary.truePositive, summary.predicted)} | ${percent(summary.truePositive, summary.total)} | ${percent(summary.labelPassed, summary.total)} | ${percent(summary.confidencePassed, summary.total)} | ${percent(summary.concernsPassed, summary.total)} |`,
    );
  }

  const truePositiveRecords = records.filter(
    (record) => record.testCase.category === "true-positive",
  );
  const falsePositiveRecords = records.filter(
    (record) => record.testCase.category === "false-positive",
  );
  const truePositiveAcceptance = truePositiveRecords.filter(
    (record) => record.actual.valid && record.labelPassed,
  ).length;
  const falsePositiveRejections = falsePositiveRecords.filter(
    (record) => !record.actual.valid && record.labelPassed,
  ).length;
  const confidentlyWrong = records.filter(
    (record) =>
      !record.labelPassed &&
      record.actual.confidence > CONFIDENTLY_WRONG_THRESHOLD,
  );

  lines.push(
    "",
    `True-positive acceptance: ${truePositiveAcceptance}/${truePositiveRecords.length} (${percent(truePositiveAcceptance, truePositiveRecords.length)})`,
    `False-positive rejection: ${falsePositiveRejections}/${falsePositiveRecords.length} (${percent(falsePositiveRejections, falsePositiveRecords.length)})`,
    `Confidently wrong calls: ${confidentlyWrong.length}`,
  );

  if (confidentlyWrong.length > 0) {
    lines.push("", "### Confidently Wrong Cases", "");
    for (const record of confidentlyWrong) {
      lines.push(
        `- ${record.testCase.name}: expected ${record.testCase.expected.valid}/${record.testCase.expected.findingType}, got ${record.actual.valid}/${record.actual.findingType} at confidence ${record.actual.confidence}`,
      );
    }
  }

  return `${lines.join("\n")}\n`;
}

function logSummary(records: EvalRecord[]): void {
  const markdown = buildSummaryMarkdown(records);
  console.log(`\n${markdown}`);

  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  }
}

describeIfEnabled("Finding Judge evals", () => {
  it(
    "meets labeled seed dataset expectations",
    async () => {
      const records: EvalRecord[] = [];

      for (const testCase of judgeEvalCases) {
        const actual = await judgeFinding(testCase.input, EVAL_MODEL);
        const evaluation = evaluateRecord(testCase, actual);

        records.push({
          testCase,
          actual,
          ...evaluation,
        });
      }

      logSummary(records);

      const failures = records
        .filter((record) => !record.passed)
        .map((record) => ({
          name: record.testCase.name,
          category: record.testCase.category,
          expected: record.testCase.expected,
          actual: {
            valid: record.actual.valid,
            findingType: record.actual.findingType,
            confidence: record.actual.confidence,
            reasoning: record.actual.reasoning,
            concerns: record.actual.concerns,
            error: record.actual.error,
          },
          checks: {
            labelPassed: record.labelPassed,
            confidencePassed: record.confidencePassed,
            concernsPassed: record.concernsPassed,
          },
        }));

      const truePositiveRecords = records.filter(
        (record) => record.testCase.category === "true-positive",
      );
      const falsePositiveRecords = records.filter(
        (record) => record.testCase.category === "false-positive",
      );
      const truePositiveAcceptance =
        truePositiveRecords.filter(
          (record) => record.actual.valid && record.labelPassed,
        ).length / truePositiveRecords.length;
      const falsePositiveRejection =
        falsePositiveRecords.filter(
          (record) => !record.actual.valid && record.labelPassed,
        ).length / falsePositiveRecords.length;
      const confidentlyWrong = records.filter(
        (record) =>
          !record.labelPassed &&
          record.actual.confidence > CONFIDENTLY_WRONG_THRESHOLD,
      );

      expect(failures).toEqual([]);
      expect(truePositiveAcceptance).toBeGreaterThanOrEqual(
        TRUE_POSITIVE_TARGET,
      );
      expect(falsePositiveRejection).toBeGreaterThanOrEqual(
        FALSE_POSITIVE_REJECTION_TARGET,
      );
      expect(confidentlyWrong).toHaveLength(0);
    },
    EVAL_TIMEOUT_MS,
  );
});
