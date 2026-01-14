/**
 * Orchestrator Agent
 *
 * LLM-based orchestrator that analyzes attack surface results and
 * creates intelligent test plans, replacing heuristics-based
 * vulnerability class inference.
 */

import { hasToolCall } from 'ai';
import { streamResponse } from '../../ai';
import type {
  OrchestratorAgentInput,
  OrchestratorAgentResult,
  TestPlan,
} from './types';
import { ORCHESTRATOR_SYSTEM_PROMPT, buildOrchestratorUserPrompt } from './prompts/orchestrator';
import { createTestPlanTool, createAnalyzeTargetTool } from './tools';

/**
 * Run the orchestrator agent to create a test plan
 */
export async function runOrchestratorAgent(
  input: OrchestratorAgentInput
): Promise<OrchestratorAgentResult> {
  const { attackSurfaceResults, session, model, onProgress, abortSignal } = input;

  try {
    onProgress?.('Analyzing attack surface results...');

    // Build context from attack surface results
    const userPrompt = buildOrchestratorUserPrompt({
      discoveredAssets: attackSurfaceResults.discoveredAssets || [],
      targets: attackSurfaceResults.targets || [],
      keyFindings: attackSurfaceResults.keyFindings || [],
      summary: attackSurfaceResults.summary,
    });

    // Create tools
    const tools = {
      create_test_plan: createTestPlanTool(session),
      analyze_target: createAnalyzeTargetTool(),
    };

    onProgress?.('Creating test plan...');

    // Run the agent
    const streamResult = streamResponse({
      prompt: userPrompt,
      system: ORCHESTRATOR_SYSTEM_PROMPT,
      model,
      tools,
      stopWhen: hasToolCall('create_test_plan'),
      abortSignal,
    });

    // Consume stream to completion
    for await (const chunk of streamResult.fullStream) {
      // Just consume the stream
      if (chunk.type === 'error') {
        throw (chunk as any).error;
      }
    }

    // Get tool calls from the response
    const toolCalls = await streamResult.toolCalls;

    // Extract test plan from tool call
    const testPlanCall = toolCalls.find((tc: any) => tc.toolName === 'create_test_plan');

    if (!testPlanCall) {
      return {
        testPlan: {
          tests: [],
          reasoning: 'Agent did not create a test plan',
          createdAt: new Date().toISOString(),
        },
        success: false,
        error: 'Agent did not call create_test_plan',
      };
    }

    const args = (testPlanCall as any).input as { tests: any[]; reasoning: string };
    const testPlan: TestPlan = {
      tests: args.tests,
      reasoning: args.reasoning,
      createdAt: new Date().toISOString(),
    };

    onProgress?.(`Test plan created with ${testPlan.tests.length} tests`);

    return {
      testPlan,
      success: true,
    };
  } catch (error: any) {
    return {
      testPlan: {
        tests: [],
        reasoning: '',
        createdAt: new Date().toISOString(),
      },
      success: false,
      error: error.message || 'Unknown error',
    };
  }
}
