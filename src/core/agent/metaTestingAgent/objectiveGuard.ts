/**
 * Objective Guard
 *
 * Enforces objective focus for meta testing agents. Prevents silent pivots
 * and ensures agents either stick to their objectives or properly spawn
 * sub-agents for discovered vulnerabilities.
 */

import { tool } from 'ai';
import { z } from 'zod';
import type { VulnerabilityClass } from '../orchestrator/types';
import type { SpawnVulnerabilityTestRequest } from './metaVulnerabilityTestAgent';

/**
 * State tracking for objective focus
 */
export interface ObjectiveState {
  /** Original objective assigned to this agent */
  originalObjective: string;

  /** Original vulnerability class assigned */
  originalVulnClass: VulnerabilityClass;

  /** Current focus description */
  currentFocus: string;

  /** Number of times the agent has pivoted within its objective */
  pivotCount: number;

  /** Evidence gathered for the original objective */
  evidenceForObjective: string[];

  /** If agent was killed, the reason why */
  abandonmentReason?: string;
}

/**
 * Decision outcome from objective evaluation
 */
export interface ObjectiveDecision {
  /** What action the agent should take */
  action: 'continue' | 'spawn_and_continue' | 'spawn_and_kill' | 'kill';

  /** Reason for this decision */
  reason: string;

  /** If spawning, the request details */
  spawnRequest?: SpawnVulnerabilityTestRequest;
}

/**
 * Input schema for evaluate_objective_progress tool
 */
export const EvaluateObjectiveProgressSchema = z.object({
  currentEvidence: z.string().describe(
    'Evidence gathered so far for your assigned objective. Be specific about what you found.'
  ),
  confidenceInObjective: z.number().min(0).max(100).describe(
    'Your confidence (0-100) that the assigned vulnerability exists and can be exploited'
  ),
  discoveredIndicator: z.object({
    vulnClass: z.string().describe('The vulnerability class you discovered indicators for'),
    evidence: z.string().describe('Evidence of this different vulnerability'),
    confidence: z.number().min(0).max(100).describe('Confidence in this discovery'),
  }).optional().describe(
    'If you found indicators of a DIFFERENT vulnerability type than your assignment, describe it here'
  ),
  proposedAction: z.enum(['continue', 'pivot', 'spawn', 'abandon']).describe(
    'What you propose to do: continue testing, pivot approach, spawn new agent, or abandon'
  ),
  reasoning: z.string().describe('Detailed reasoning for your proposed action'),
});

export type EvaluateObjectiveProgressInput = z.infer<typeof EvaluateObjectiveProgressSchema>;

/**
 * Create the objective guard tool and state tracker
 */
export function createObjectiveGuard(
  initialObjective: string,
  vulnClass: VulnerabilityClass,
  target: string,
  onSpawnAgent?: (request: SpawnVulnerabilityTestRequest) => void
) {
  const state: ObjectiveState = {
    originalObjective: initialObjective,
    originalVulnClass: vulnClass,
    currentFocus: initialObjective,
    pivotCount: 0,
    evidenceForObjective: [],
  };

  const evaluate_objective_progress = tool({
    description: `Evaluate your progress toward the assigned objective.

**MANDATORY**: Call this tool before:
- Any significant pivot to a different approach
- When you discover indicators of a DIFFERENT vulnerability type
- When you're considering abandoning the objective

**Decision outcomes:**
- \`continue\`: Keep testing current objective
- \`spawn_and_continue\`: Spawn new agent for discovery, continue your testing
- \`spawn_and_kill\`: Spawn new agent, then terminate (discovery more promising)
- \`kill\`: Terminate testing (no evidence, exhausted approaches)

**Rules:**
- You CANNOT silently abandon your objective
- If you find a different vuln type, you MUST spawn a new agent for it
- Only kill testing after 3+ different approaches with <25% confidence`,
    inputSchema: EvaluateObjectiveProgressSchema,
    execute: async (params: EvaluateObjectiveProgressInput): Promise<ObjectiveDecision> => {
      const {
        currentEvidence,
        confidenceInObjective,
        discoveredIndicator,
        proposedAction,
        reasoning,
      } = params;

      // Record evidence
      if (currentEvidence && currentEvidence.trim()) {
        state.evidenceForObjective.push(currentEvidence);
      }

      // RULE 1: If objective confidence > 50%, always continue
      if (confidenceInObjective > 50) {
        return {
          action: 'continue',
          reason: `Objective confidence ${confidenceInObjective}% > 50%. Continue testing your assigned objective (${state.originalVulnClass}).`,
        };
      }

      // RULE 2: If discovered new vuln with high confidence, spawn new agent
      if (discoveredIndicator && discoveredIndicator.confidence > 70) {
        state.pivotCount++;

        const spawnRequest: SpawnVulnerabilityTestRequest = {
          target,
          objective: `Test for ${discoveredIndicator.vulnClass} based on: ${discoveredIndicator.evidence}`,
          vulnerabilityClass: discoveredIndicator.vulnClass,
          evidence: discoveredIndicator.evidence,
          priority: discoveredIndicator.confidence > 85 ? 'critical' : 'high',
        };

        // If objective confidence is very low and we found something much better
        if (confidenceInObjective < 25 && discoveredIndicator.confidence > 80) {
          state.abandonmentReason = `Low confidence (${confidenceInObjective}%) in ${state.originalVulnClass}, high confidence (${discoveredIndicator.confidence}%) in ${discoveredIndicator.vulnClass}`;

          if (onSpawnAgent) {
            onSpawnAgent(spawnRequest);
          }

          return {
            action: 'spawn_and_kill',
            reason: `Objective confidence ${confidenceInObjective}% very low. Discovered ${discoveredIndicator.vulnClass} with ${discoveredIndicator.confidence}% confidence. Spawning new agent and terminating this one.`,
            spawnRequest,
          };
        }

        // Otherwise spawn and continue with original objective
        if (onSpawnAgent) {
          onSpawnAgent(spawnRequest);
        }

        return {
          action: 'spawn_and_continue',
          reason: `Spawned ${discoveredIndicator.vulnClass} agent for the discovery. Continue testing your original objective (${state.originalVulnClass}).`,
          spawnRequest,
        };
      }

      // RULE 3: If confidence < 25% and 3+ pivots with no evidence, consider killing
      if (confidenceInObjective < 25 && state.pivotCount >= 3) {
        const hasAnyEvidence = state.evidenceForObjective.some(e => e.trim().length > 0);

        if (!hasAnyEvidence) {
          state.abandonmentReason = `No evidence after ${state.pivotCount} different approaches, confidence ${confidenceInObjective}%`;

          return {
            action: 'kill',
            reason: `Objective confidence ${confidenceInObjective}% < 25% after ${state.pivotCount} pivots. No meaningful evidence found. Terminating to save resources.`,
          };
        }
      }

      // RULE 4: If proposing to pivot, increment counter and allow
      if (proposedAction === 'pivot') {
        state.pivotCount++;
        return {
          action: 'continue',
          reason: `Pivot approved (pivot #${state.pivotCount}). Continue testing ${state.originalVulnClass} with new approach. Current confidence: ${confidenceInObjective}%`,
        };
      }

      // Default: continue testing
      return {
        action: 'continue',
        reason: `Continue testing. Current confidence in ${state.originalVulnClass}: ${confidenceInObjective}%. Pivots so far: ${state.pivotCount}.`,
      };
    },
  });

  return {
    evaluate_objective_progress,
    state,
    getState: () => ({ ...state }),
  };
}

/**
 * Prompt section for objective focus rules
 */
export function getObjectiveFocusPrompt(
  objective: string,
  vulnClass: VulnerabilityClass
): string {
  return `
## CRITICAL: Objective Focus Rules

**Your assigned objective:** ${objective}
**Your assigned vulnerability class:** ${vulnClass}

### Rules

1. **STAY ON TARGET**: Your primary job is to find vulnerabilities matching your assignment (${vulnClass})
2. **DISCOVERIES**: If you find indicators of a DIFFERENT vulnerability type:
   - Call \`evaluate_objective_progress\` IMMEDIATELY
   - Do NOT simply pivot away from your objective
   - Either spawn a new agent OR justify abandonment
3. **NO SILENT PIVOTS**: You CANNOT change focus without using \`evaluate_objective_progress\`
4. **KILL CRITERIA**: Terminate if:
   - Confidence < 25% AND exhausted 3+ different approaches AND no evidence
   - \`evaluate_objective_progress\` returns action: 'kill'

### Spawning New Agents

When you discover indicators of a DIFFERENT vulnerability type:

1. **Strong indicator (confidence > 70%)**: Call \`evaluate_objective_progress\`
2. **The tool will decide**: spawn_and_continue, spawn_and_kill, or continue
3. **Follow its decision**: Do not override the objective guard

**Examples of when to spawn:**
- Testing SQLi but see "phar://" in error → spawn deserialization agent
- Testing LFI but see "{{7*7}}" evaluated → spawn SSTI agent
- Testing XSS but see "JWT" handling weakness → spawn crypto agent

**Examples of when NOT to spawn:**
- Vague indicators without evidence
- Same vulnerability class as your assignment
- Low confidence discoveries (< 50%)

### Shared Memory on Pivot

When pivoting to a new approach (confidence < 50%), you MUST:
1. Call \`record_approach\` for the failed approach (so others learn)
2. Query shared memory via \`get_relevant_approaches\` for your vuln class
3. Prioritize approaches that worked for similar targets
4. Avoid approaches with learned constraints
`;
}
