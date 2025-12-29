/**
 * Action Suggestions for Operator Mode
 *
 * Provides contextual suggestions based on current stage and findings.
 */

import type { OperatorStage, ActionHistoryEntry } from "../../operator";
import { OPERATOR_STAGES } from "../../operator";

export interface ActionSuggestion {
  id: string;
  label: string;
  description: string;
  directive: string;
  stage: OperatorStage;
  priority: "high" | "medium" | "low";
}

/**
 * Get suggested actions for the current stage
 */
export function getSuggestedActions(
  currentStage: OperatorStage,
  actionHistory: ActionHistoryEntry[],
  context?: {
    target?: string;
    findingsCount?: number;
    endpointsFound?: number;
  }
): ActionSuggestion[] {
  const stageDef = OPERATOR_STAGES[currentStage];
  const suggestions: ActionSuggestion[] = [];

  // Add stage-specific suggestions
  const stageSuggestions = getStageSpecificSuggestions(currentStage, context);
  suggestions.push(...stageSuggestions);

  // Filter out actions that have already been completed
  const completedActions = new Set(
    actionHistory
      .filter((a) => a.decision === "approved" || a.decision === "auto-approved")
      .map((a) => a.toolName)
  );

  // Add "advance to next stage" suggestion if we've done some work
  if (actionHistory.length >= 3) {
    suggestions.push({
      id: "advance-stage",
      label: "Advance to next stage",
      description: `Move to the next phase of testing`,
      directive: "Let's advance to the next testing stage. Summarize what we found and move on.",
      stage: currentStage,
      priority: "medium",
    });
  }

  return suggestions.slice(0, 6); // Limit to 6 suggestions
}

/**
 * Get stage-specific suggestions
 */
function getStageSpecificSuggestions(
  stage: OperatorStage,
  context?: { target?: string; findingsCount?: number; endpointsFound?: number }
): ActionSuggestion[] {
  const target = context?.target || "the target";

  switch (stage) {
    case "setup":
      return [
        {
          id: "verify-target",
          label: "Verify target",
          description: "Check that the target is accessible",
          directive: `Verify that ${target} is accessible and responding`,
          stage,
          priority: "high",
        },
        {
          id: "check-scope",
          label: "Review scope",
          description: "Review allowed testing boundaries",
          directive: "Review the scope constraints and confirm what we're allowed to test",
          stage,
          priority: "medium",
        },
      ];

    case "recon":
      return [
        {
          id: "crawl-app",
          label: "Crawl application",
          description: "Discover pages and endpoints",
          directive: `Crawl ${target} to discover all accessible pages and endpoints`,
          stage,
          priority: "high",
        },
        {
          id: "identify-tech",
          label: "Identify technologies",
          description: "Fingerprint frameworks and services",
          directive: "Identify the technologies, frameworks, and services used by this application",
          stage,
          priority: "high",
        },
        {
          id: "find-apis",
          label: "Find API endpoints",
          description: "Look for REST/GraphQL APIs",
          directive: "Search for API endpoints - REST, GraphQL, or other API patterns",
          stage,
          priority: "medium",
        },
        {
          id: "check-robots",
          label: "Check robots.txt",
          description: "Look for hidden paths",
          directive: "Check robots.txt and sitemap.xml for hidden or interesting paths",
          stage,
          priority: "medium",
        },
      ];

    case "enumerate":
      return [
        {
          id: "map-params",
          label: "Map parameters",
          description: "Find all input parameters",
          directive: "Map all input parameters across the discovered endpoints",
          stage,
          priority: "high",
        },
        {
          id: "find-auth-endpoints",
          label: "Find auth endpoints",
          description: "Locate login, register, password reset",
          directive: "Find all authentication-related endpoints: login, register, password reset, etc.",
          stage,
          priority: "high",
        },
        {
          id: "identify-ids",
          label: "Find ID patterns",
          description: "Look for sequential or predictable IDs",
          directive: "Identify ID patterns in URLs and parameters that might be vulnerable to IDOR",
          stage,
          priority: "medium",
        },
      ];

    case "test":
      return [
        {
          id: "test-sqli",
          label: "Test SQL injection",
          description: "Probe for SQLi vulnerabilities",
          directive: "Test all identified parameters for SQL injection vulnerabilities",
          stage,
          priority: "high",
        },
        {
          id: "test-xss",
          label: "Test XSS",
          description: "Probe for cross-site scripting",
          directive: "Test input fields for reflected and stored XSS vulnerabilities",
          stage,
          priority: "high",
        },
        {
          id: "test-idor",
          label: "Test IDOR",
          description: "Check for insecure direct object references",
          directive: "Test for IDOR by manipulating ID parameters",
          stage,
          priority: "high",
        },
        {
          id: "test-auth",
          label: "Test authentication",
          description: "Check auth bypass and session handling",
          directive: "Test authentication mechanisms for bypass vulnerabilities and weak session handling",
          stage,
          priority: "medium",
        },
        {
          id: "test-authz",
          label: "Test authorization",
          description: "Check privilege escalation",
          directive: "Test authorization boundaries - can lower-privileged users access admin functions?",
          stage,
          priority: "medium",
        },
      ];

    case "validate":
      return [
        {
          id: "verify-findings",
          label: "Verify findings",
          description: "Confirm discovered vulnerabilities",
          directive: "Verify each discovered vulnerability to confirm it's exploitable",
          stage,
          priority: "high",
        },
        {
          id: "create-pocs",
          label: "Create POCs",
          description: "Generate proof-of-concept scripts",
          directive: "Create proof-of-concept scripts for each confirmed vulnerability",
          stage,
          priority: "high",
        },
        {
          id: "assess-impact",
          label: "Assess impact",
          description: "Determine severity and business impact",
          directive: "Assess the impact and severity of each confirmed finding",
          stage,
          priority: "medium",
        },
      ];

    case "report":
      return [
        {
          id: "generate-report",
          label: "Generate report",
          description: "Create final penetration test report",
          directive: "Generate the final penetration test report with all findings",
          stage,
          priority: "high",
        },
        {
          id: "review-findings",
          label: "Review findings",
          description: "Summary of all discovered issues",
          directive: "Provide a summary of all findings discovered during this assessment",
          stage,
          priority: "high",
        },
      ];

    default:
      return [];
  }
}

/**
 * Get quick action suggestions (for toolbar/shortcuts)
 */
export function getQuickActions(stage: OperatorStage): Array<{ key: string; label: string; directive: string }> {
  switch (stage) {
    case "recon":
      return [
        { key: "c", label: "Crawl", directive: "Crawl the application to discover endpoints" },
        { key: "t", label: "Tech", directive: "Identify technologies used" },
      ];
    case "test":
      return [
        { key: "s", label: "SQLi", directive: "Test for SQL injection" },
        { key: "x", label: "XSS", directive: "Test for XSS" },
        { key: "i", label: "IDOR", directive: "Test for IDOR" },
      ];
    case "validate":
      return [
        { key: "p", label: "POC", directive: "Create POCs for findings" },
        { key: "v", label: "Verify", directive: "Verify findings" },
      ];
    default:
      return [];
  }
}
