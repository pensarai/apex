/**
 * Plan Memory Tools
 *
 * Tools for storing and retrieving strategic plans and adaptations.
 * Plans are stored as JSON files in the session directory.
 *
 * - Plans as external working memory
 * - Checkpoint protocol at 20%/40%/60%/80% budget
 * - Adaptations track what worked/failed for meta-prompting
 */

import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { existsSync, writeFileSync, readFileSync } from "fs";
import { Logger } from "../logger";
import type { PentestPlan, Adaptation, MetaTestingSessionInfo } from "./types";
import { StorePlanSchema, StoreAdaptationSchema } from "./types";

export const BUDGET_CHECKPOINTS = [20, 40, 60, 80];

export function createPlanMemoryTools(
  session: MetaTestingSessionInfo,
  logger: Logger
) {
  const planPath = join(session.rootPath, "plan.json");
  const adaptationsPath = join(session.rootPath, "adaptations.json");

  const store_plan = tool({
    description: `Store or update the strategic pentest plan.

**REQUIRED at step 0:** Create initial plan with phases.
**REQUIRED at checkpoints:** Update after get_plan at 20%/40%/60%/80% budget.

Plan structure:
- objective: Main goal of the pentest
- target: Primary target URL
- current_phase: Active phase number (1-indexed)
- total_phases: Total number of planned phases
- budget_used: Estimated budget utilization (0-100%)
- phases: Array of phase objects with id, title, status, criteria, attempts

Phase statuses:
- 'pending': Not yet started
- 'active': Currently working on
- 'done': Criteria met, completed
- 'blocked': Cannot proceed, external blocker
- 'partial_failure': Some progress but didn't fully succeed`,
    inputSchema: StorePlanSchema,
    execute: async (plan) => {
      try {
        const timestamp = new Date().toISOString();

        // Load existing plan to preserve history
        let existingPlan: Partial<PentestPlan> = {};
        if (existsSync(planPath)) {
          try {
            existingPlan = JSON.parse(readFileSync(planPath, "utf-8"));
          } catch {
            // Ignore parse errors, start fresh
          }
        }

        const fullPlan: PentestPlan = {
          ...plan,
          created_at: existingPlan.created_at || timestamp,
          updated_at: timestamp,
        };

        writeFileSync(planPath, JSON.stringify(fullPlan, null, 2));
        logger.info(
          `Plan stored: Phase ${plan.current_phase}/${plan.total_phases}, Budget: ${plan.budget_used}%`
        );

        const checkpoint = BUDGET_CHECKPOINTS.find(
          (cp) => plan.budget_used >= cp && plan.budget_used < cp + 20
        );

        let checkpointMsg = "";
        if (checkpoint) {
          checkpointMsg = `\n\n**Checkpoint ${checkpoint}% reached.** Next checkpoint at ${
            checkpoint + 20
          }%.`;
        }

        return {
          success: true,
          message: `Plan updated successfully.

**Current State:**
- Phase: ${plan.current_phase}/${plan.total_phases} - "${
            plan.phases.find((p) => p.status === "active")?.title ||
            "None active"
          }"
- Budget used: ${plan.budget_used}%
- Phases completed: ${plan.phases.filter((p) => p.status === "done").length}/${
            plan.total_phases
          }${checkpointMsg}`,
        };
      } catch (error: any) {
        logger.error(`Failed to store plan: ${error.message}`);
        return {
          success: false,
          error: error.message,
          message: `Failed to store plan: ${error.message}`,
        };
      }
    },
  });

  const get_plan = tool({
    description: `Retrieve the current strategic plan.

**MANDATORY at checkpoints:** Call at 20%/40%/60%/80% budget utilization.

After retrieving:
1. Evaluate: Are current phase criteria met?
2. If YES: Update phase status to 'done', advance current_phase
3. If NO but stuck: Consider calling optimize_prompt, then pivot
4. Call store_plan with updated status

This helps maintain strategic coherence across long operations.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Retrieving current pentest plan')"
        ),
    }),
    execute: async () => {
      try {
        if (!existsSync(planPath)) {
          return {
            success: false,
            error: "NO_PLAN",
            message: `No plan found. Create initial plan with store_plan tool.

**Required:** At step 0, create a plan with:
- Phases for your testing approach
- Clear criteria for each phase
- Budget estimates`,
          };
        }

        const plan: PentestPlan = JSON.parse(readFileSync(planPath, "utf-8"));
        logger.info(
          `Plan retrieved: Phase ${plan.current_phase}/${plan.total_phases}`
        );

        // Format phases for display
        const phasesDisplay = plan.phases
          .map((p) => {
            const statusEmoji =
              {
                active: "▶️",
                pending: "⏳",
                done: "✅",
                blocked: "🚫",
                partial_failure: "⚠️",
              }[p.status] || "❓";
            return `  ${statusEmoji} Phase ${p.id}: ${p.title} [${p.status}] - ${p.criteria}`;
          })
          .join("\n");

        const nextCheckpoint = BUDGET_CHECKPOINTS.find(
          (cp) => plan.budget_used < cp
        );

        return {
          success: true,
          plan,
          message: `**Current Plan:**

Objective: ${plan.objective}
Target: ${plan.target}
Current Phase: ${plan.current_phase}/${plan.total_phases}
Budget Used: ${plan.budget_used}%
${
  nextCheckpoint
    ? `Next Checkpoint: ${nextCheckpoint}%`
    : "All checkpoints passed"
}

**Phases:**
${phasesDisplay}

**VALIDATION REQUIRED:**
1. Are current phase criteria met?
2. Should you advance to next phase?
3. Need to pivot or call optimize_prompt?

Update plan with store_plan after evaluation.`,
        };
      } catch (error: any) {
        logger.error(`Failed to get plan: ${error.message}`);
        return {
          success: false,
          error: error.message,
          message: `Failed to retrieve plan: ${error.message}`,
        };
      }
    },
  });

  const store_adaptation = tool({
    description: `Record an approach outcome for meta-prompting.

**Call after each significant attempt:**
- worked=true: Approach succeeded, will be emphasized
- worked=false: Approach failed, will be de-prioritized
- constraint_learned: Specific blocker discovered (e.g., "WAF blocks <script>")

This data is used by optimize_prompt to:
- Remove exhausted tactics from guidance
- Emphasize working approaches
- Track learned constraints

**Examples:**
- worked=true, approach="UNION-based SQLi on /api/users"
- worked=false, approach="XSS via img onerror", constraint_learned="CSP blocks inline event handlers"`,
    inputSchema: StoreAdaptationSchema,
    execute: async (adaptation) => {
      try {
        let adaptations: Adaptation[] = [];
        if (existsSync(adaptationsPath)) {
          try {
            adaptations = JSON.parse(readFileSync(adaptationsPath, "utf-8"));
          } catch {
            adaptations = [];
          }
        }

        const newAdaptation: Adaptation = {
          ...adaptation,
          timestamp: Date.now(),
        };
        adaptations.push(newAdaptation);

        writeFileSync(adaptationsPath, JSON.stringify(adaptations, null, 2));

        const workedCount = adaptations.filter((a) => a.worked).length;
        const failedCount = adaptations.filter((a) => !a.worked).length;
        const constraintsCount = adaptations.filter(
          (a) => a.constraint_learned
        ).length;

        logger.info(
          `Adaptation stored: ${adaptation.approach} (${
            adaptation.worked ? "SUCCESS" : "FAILED"
          })`
        );

        return {
          success: true,
          message: `Adaptation recorded: ${
            adaptation.worked ? "✅ SUCCESS" : "❌ FAILED"
          }

Approach: "${adaptation.approach}"
${
  adaptation.constraint_learned
    ? `Constraint learned: "${adaptation.constraint_learned}"`
    : ""
}

**Running totals:**
- Successful approaches: ${workedCount}
- Failed approaches: ${failedCount}
- Constraints discovered: ${constraintsCount}

${
  failedCount >= 3 && !adaptation.worked
    ? "\n**Consider calling optimize_prompt** to update execution guidance with learned patterns."
    : ""
}`,
        };
      } catch (error: any) {
        logger.error(`Failed to store adaptation: ${error.message}`);
        return {
          success: false,
          error: error.message,
          message: `Failed to store adaptation: ${error.message}`,
        };
      }
    },
  });

  return {
    store_plan,
    get_plan,
    store_adaptation,
  };
}

export function loadAdaptations(sessionRootPath: string): Adaptation[] {
  const adaptationsPath = join(sessionRootPath, "adaptations.json");

  if (!existsSync(adaptationsPath)) {
    return [];
  }

  try {
    return JSON.parse(readFileSync(adaptationsPath, "utf-8"));
  } catch {
    return [];
  }
}

export function loadPlan(sessionRootPath: string): PentestPlan | null {
  const planPath = join(sessionRootPath, "plan.json");

  if (!existsSync(planPath)) {
    return null;
  }

  try {
    return JSON.parse(readFileSync(planPath, "utf-8"));
  } catch {
    return null;
  }
}
