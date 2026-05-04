/**
 * Permission policy for operator tool approvals.
 */

import type { PermissionTier, ToolClassification } from "./types";

export interface PermissionPolicyConfig {
  requireApproval: boolean;
  autoApproveUpToTier?: PermissionTier;
  allowApprovalBypass?: boolean;
}

export interface PermissionCheckResult {
  allowed: boolean;
  autoApproved: boolean;
  reason: string;
}

export function checkPermission(
  config: PermissionPolicyConfig,
  classification?: ToolClassification,
): PermissionCheckResult {
  if (config.allowApprovalBypass || !config.requireApproval) {
    return {
      allowed: true,
      autoApproved: true,
      reason: "Command approval is explicitly bypassed",
    };
  }

  if (
    classification &&
    config.autoApproveUpToTier !== undefined &&
    classification.tier <= config.autoApproveUpToTier
  ) {
    return {
      allowed: true,
      autoApproved: true,
      reason: `Auto-approved T${classification.tier} ${classification.intent} action`,
    };
  }

  return {
    allowed: true,
    autoApproved: false,
    reason: "Command approval is required",
  };
}

export function shouldAutoApprove(
  config: PermissionPolicyConfig,
  classification?: ToolClassification,
): boolean {
  return checkPermission(config, classification).autoApproved;
}

export function getApprovalRequirement(
  config: PermissionPolicyConfig,
): "auto" | "threshold" | "manual" {
  if (config.allowApprovalBypass || !config.requireApproval) return "auto";
  return config.autoApproveUpToTier !== undefined ? "threshold" : "manual";
}

export function getPolicySummary(config: PermissionPolicyConfig): string {
  if (config.allowApprovalBypass || !config.requireApproval) {
    return "Command approval disabled — tool calls execute automatically";
  }
  if (config.autoApproveUpToTier !== undefined) {
    return `Command approval threshold — auto-approve T1-T${config.autoApproveUpToTier}, prompt above`;
  }
  return "Command approval enabled — every tool call requires approval";
}
