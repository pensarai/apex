/**
 * Target Extractor
 *
 * Uses LLM to extract (target, objective) as PentestTarget from user's natural language message.
 * Handles @mentions of endpoints and infers objectives from context.
 */

import { z } from 'zod';
import { generateObjectResponse, type AIModel } from '../../ai';
import type { PentestTarget } from '../attackSurfaceAgent/types';

/**
 * Endpoint discovered during recon that can be @mentioned
 */
export interface DiscoveredEndpoint {
  id: string;
  url: string;
  method: string;
  suggestedObjective: string;
  source: 'recon' | 'manual';
}

/**
 * Input for target extraction
 */
export interface ExtractTargetInput {
  /** The user's message (may contain @mentions) */
  userMessage: string;
  /** List of discovered endpoints that can be @mentioned */
  discoveredEndpoints: DiscoveredEndpoint[];
  /** AI model to use for extraction */
  model: AIModel;
  /** Optional callback for token usage tracking */
  onTokenUsage?: (inputTokens: number, outputTokens: number) => void;
}

/**
 * Schema for extracted target
 */
const ExtractedTargetSchema = z.object({
  target: z.string().describe('The target URL to test'),
  objective: z.string().describe('What to test for / the security objective'),
  reasoning: z.string().describe('Why this target and objective were extracted'),
  confidence: z.enum(['high', 'medium', 'low']).describe('Confidence in the extraction'),
});

type ExtractedTarget = z.infer<typeof ExtractedTargetSchema>;

/**
 * Parse @mentions from user message
 * Returns the ID of mentioned endpoints
 */
export function parseAtMentions(message: string): string[] {
  const mentionRegex = /@(\S+)/g;
  const mentions: string[] = [];
  let match;
  while ((match = mentionRegex.exec(message)) !== null) {
    mentions.push(match[1]);
  }
  return mentions;
}

/**
 * Find endpoint by ID or partial URL match
 */
export function findEndpoint(
  mention: string,
  endpoints: DiscoveredEndpoint[]
): DiscoveredEndpoint | undefined {
  // Try exact ID match first
  let endpoint = endpoints.find(e => e.id === mention);
  if (endpoint) return endpoint;

  // Try URL contains match
  endpoint = endpoints.find(e => e.url.includes(mention) || mention.includes(e.url));
  if (endpoint) return endpoint;

  // Try index match (e.g., @1, @2)
  const index = parseInt(mention, 10);
  if (!isNaN(index) && index >= 0 && index < endpoints.length) {
    return endpoints[index];
  }

  return undefined;
}

/**
 * Extract PentestTarget from user message
 *
 * Handles:
 * - Direct @mentions of endpoints
 * - Natural language descriptions of targets
 * - Objective inference from context
 */
export async function extractPentestTarget(
  input: ExtractTargetInput
): Promise<PentestTarget> {
  const { userMessage, discoveredEndpoints, model, onTokenUsage } = input;

  // First, check for @mentions
  const mentions = parseAtMentions(userMessage);
  if (mentions.length > 0) {
    // Find the first valid endpoint mention
    for (const mention of mentions) {
      const endpoint = findEndpoint(mention, discoveredEndpoints);
      if (endpoint) {
        // Extract objective from the rest of the message or use default
        const objectiveFromMessage = extractObjectiveFromMessage(userMessage, endpoint);
        return {
          target: endpoint.url,
          objective: objectiveFromMessage || endpoint.suggestedObjective,
          rationale: `User mentioned endpoint @${mention}`,
        };
      }
    }
  }

  // If no valid @mention, use LLM to extract target and objective
  const endpointsList = discoveredEndpoints.length > 0
    ? discoveredEndpoints.map((e, i) => `${i}. ${e.url} - ${e.suggestedObjective}`).join('\n')
    : 'No discovered endpoints available.';

  const prompt = `You are helping extract a penetration testing target and objective from a user's message.

Available discovered endpoints:
${endpointsList}

User's message:
"${userMessage}"

Extract the target URL and testing objective. If the user mentions a specific endpoint or URL, use that.
If they describe what to test (e.g., "test the login for SQL injection"), infer the appropriate target and objective.
If they're vague, use the most relevant discovered endpoint or ask for clarification by setting confidence to "low".

Return a JSON object with:
- target: The URL to test
- objective: What security testing to perform
- reasoning: Brief explanation of your extraction
- confidence: high/medium/low based on clarity of the request`;

  try {
    const result = await generateObjectResponse({
      model,
      schema: ExtractedTargetSchema,
      prompt,
      maxTokens: 500,
      temperature: 0.3,
      onTokenUsage,
    });

    return {
      target: result.target,
      objective: result.objective,
      rationale: result.reasoning,
    };
  } catch (error) {
    // Fallback: If we have discovered endpoints, use the first one
    if (discoveredEndpoints.length > 0) {
      const firstEndpoint = discoveredEndpoints[0];
      return {
        target: firstEndpoint.url,
        objective: `Test: ${userMessage}`,
        rationale: 'LLM extraction failed, using first discovered endpoint',
      };
    }

    // If no endpoints, try to extract URL from message directly
    const urlMatch = userMessage.match(/https?:\/\/[^\s]+/);
    if (urlMatch) {
      return {
        target: urlMatch[0],
        objective: `Security testing as per user request: ${userMessage}`,
        rationale: 'Extracted URL directly from message',
      };
    }

    throw new Error('Could not extract target from message. Please specify a URL or @mention an endpoint.');
  }
}

/**
 * Extract objective from user message given an endpoint context
 */
function extractObjectiveFromMessage(
  message: string,
  endpoint: DiscoveredEndpoint
): string | null {
  // Remove @mentions to get the rest of the message
  const cleanMessage = message.replace(/@\S+/g, '').trim();

  if (!cleanMessage) {
    return null;
  }

  // Common testing keywords
  const testKeywords = [
    'test', 'check', 'find', 'look for', 'scan', 'attack',
    'exploit', 'verify', 'probe', 'assess', 'analyze'
  ];

  // Vulnerability keywords
  const vulnKeywords = [
    'sql', 'sqli', 'injection', 'xss', 'cross-site',
    'idor', 'authorization', 'auth', 'bypass',
    'ssrf', 'xxe', 'command', 'rce', 'lfi', 'rfi'
  ];

  const lowerMessage = cleanMessage.toLowerCase();

  // Check if message contains testing intent
  const hasTestIntent = testKeywords.some(k => lowerMessage.includes(k));
  const hasVulnType = vulnKeywords.some(k => lowerMessage.includes(k));

  if (hasTestIntent || hasVulnType) {
    return cleanMessage;
  }

  return null;
}

/**
 * Validate that a PentestTarget has required fields
 */
export function isValidPentestTarget(target: Partial<PentestTarget>): target is PentestTarget {
  return (
    typeof target.target === 'string' &&
    target.target.length > 0 &&
    typeof target.objective === 'string' &&
    target.objective.length > 0
  );
}
