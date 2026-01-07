/**
 * Stage Inference
 *
 * Automatically infers the appropriate Operator stage based on user directive.
 * Uses pattern matching to detect intent signals in user messages.
 */

import type { OperatorStage } from "./types";

export interface StageInferenceResult {
  stage: OperatorStage;
  confidence: "high" | "medium" | "low";
  reason: string;
}

/**
 * Infer the appropriate stage from a user directive.
 *
 * @param directive - The user's message/directive
 * @returns Inference result with stage and confidence, or null if unclear
 *
 * @example
 * inferStageFromDirective("Find SQL injection vulnerabilities")
 * // → { stage: "test", confidence: "high", reason: "vulnerability testing intent" }
 *
 * inferStageFromDirective("Tell me about the target")
 * // → null (no clear stage intent)
 */
export function inferStageFromDirective(directive: string): StageInferenceResult | null {
  const lower = directive.toLowerCase();

  // Report stage - documentation intent
  if (/\b(report|document|write.?up|summarize|export|generate.?report)\b/.test(lower)) {
    return { stage: "report", confidence: "high", reason: "documentation intent" };
  }

  // Validate stage - exploitation/POC intent
  if (/\b(prove|poc|exploit|demonstrate|confirm.*(vuln|finding)|verify.*(vuln|finding)|create.?poc)\b/.test(lower)) {
    return { stage: "validate", confidence: "high", reason: "exploitation/POC intent" };
  }

  // Test stage - vulnerability testing intent
  if (/\b(test|find.*(vuln|injection|xss|sqli|idor|bypass)|check.*(for|auth)|inject|fuzz|attack|exploit)\b/.test(lower)) {
    return { stage: "test", confidence: "high", reason: "vulnerability testing intent" };
  }

  // Enumerate stage - parameter/input mapping intent
  if (/\b(parameter|input|form|hidden|api.?endpoint|map.*(param|input)|catalog|inventory)\b/.test(lower)) {
    return { stage: "enumerate", confidence: "medium", reason: "parameter enumeration intent" };
  }

  // Recon stage - discovery intent
  if (/\b(explore|discover|crawl|attack.?surface|recon|find.?endpoint|enumerate|scan|fingerprint|identify)\b/.test(lower)) {
    return { stage: "recon", confidence: "high", reason: "discovery intent" };
  }

  // Setup stage - configuration intent
  if (/\b(setup|configure|set.?up|initialize|scope|target)\b/.test(lower)) {
    return { stage: "setup", confidence: "medium", reason: "configuration intent" };
  }

  // No clear intent - return null to keep current stage
  return null;
}
