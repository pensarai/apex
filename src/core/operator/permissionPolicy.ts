import type { OperatorMode, PermissionTier } from "./types";

/**
 * Permission policy configuration
 */
export interface PermissionPolicyConfig {
  mode: OperatorMode;
  autoApproveTier: PermissionTier;
}

/**
 * Result of a permission check
 */
export interface PermissionCheckResult {
  allowed: boolean;
  autoApproved: boolean;
  reason: string;
}

/**
 * Check if a tool call should be auto-approved based on policy
 */
export function checkPermission(
  tier: PermissionTier,
  config: PermissionPolicyConfig
): PermissionCheckResult {
  const { mode, autoApproveTier } = config;

  // Plan mode: block all network actions (tier > 1)
  if (mode === "plan") {
    if (tier === 1) {
      return {
        allowed: true,
        autoApproved: true,
        reason: "Passive operations allowed in plan mode",
      };
    }
    return {
      allowed: false,
      autoApproved: false,
      reason: "Plan mode - network actions blocked",
    };
  }

  // Manual mode: require approval for everything except tier 1
  if (mode === "manual") {
    if (tier === 1) {
      return {
        allowed: true,
        autoApproved: true,
        reason: "Passive operations auto-approved",
      };
    }
    return {
      allowed: true,
      autoApproved: false,
      reason: `Tier ${tier} requires manual approval`,
    };
  }

  // Auto mode: auto-approve up to configured tier
  if (mode === "auto") {
    if (tier <= autoApproveTier) {
      return {
        allowed: true,
        autoApproved: true,
        reason: `Tier ${tier} auto-approved (within T${autoApproveTier})`,
      };
    }
    return {
      allowed: true,
      autoApproved: false,
      reason: `Tier ${tier} exceeds auto-approve threshold (T${autoApproveTier})`,
    };
  }

  // Fallback - shouldn't reach here
  return {
    allowed: true,
    autoApproved: false,
    reason: "Unknown mode - requiring approval",
  };
}

/**
 * Check if an action should be blocked entirely (not just requiring approval)
 */
export function shouldBlockAction(
  tier: PermissionTier,
  mode: OperatorMode
): boolean {
  // Only plan mode blocks actions (tier > 1)
  return mode === "plan" && tier > 1;
}

/**
 * Check if an action should be auto-approved
 */
export function shouldAutoApprove(
  tier: PermissionTier,
  mode: OperatorMode,
  autoApproveTier: PermissionTier
): boolean {
  const result = checkPermission(tier, { mode, autoApproveTier });
  return result.allowed && result.autoApproved;
}

/**
 * Get the effective approval requirement for a tier given current policy
 */
export function getApprovalRequirement(
  tier: PermissionTier,
  config: PermissionPolicyConfig
): "auto" | "manual" | "blocked" {
  const result = checkPermission(tier, config);

  if (!result.allowed) {
    return "blocked";
  }
  if (result.autoApproved) {
    return "auto";
  }
  return "manual";
}

/**
 * Get a summary of what tiers are auto-approved vs manual for current config
 */
export function getPolicySummary(config: PermissionPolicyConfig): string {
  const { mode, autoApproveTier } = config;

  if (mode === "plan") {
    return "Plan mode: Only passive (T1) operations allowed";
  }

  if (mode === "manual") {
    return "Manual mode: T1 auto-approved, T2-T5 require approval";
  }

  return `Auto mode: T1-T${autoApproveTier} auto-approved, T${autoApproveTier + 1}-T5 require approval`;
}
