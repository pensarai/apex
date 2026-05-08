/**
 * Permission policy — simplified to a single boolean toggle.
 *
 * When `requireApproval` is true every tool call needs manual approval.
 * When false, all calls are auto-approved.
 */

interface PermissionPolicyConfig {
  requireApproval: boolean;
}

interface PermissionCheckResult {
  allowed: boolean;
  autoApproved: boolean;
  reason: string;
}

export function checkPermission(
  config: PermissionPolicyConfig,
): PermissionCheckResult {
  if (config.requireApproval) {
    return {
      allowed: true,
      autoApproved: false,
      reason: "Command approval is required",
    };
  }
  return {
    allowed: true,
    autoApproved: true,
    reason: "Command approval is disabled",
  };
}

export function shouldAutoApprove(config: PermissionPolicyConfig): boolean {
  return !config.requireApproval;
}

export function getApprovalRequirement(
  config: PermissionPolicyConfig,
): "auto" | "manual" {
  return config.requireApproval ? "manual" : "auto";
}

export function getPolicySummary(config: PermissionPolicyConfig): string {
  return config.requireApproval
    ? "Command approval enabled — every tool call requires approval"
    : "Command approval disabled — tool calls execute automatically";
}
