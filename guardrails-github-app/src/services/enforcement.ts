import type { ScanResponse, RepoConfig } from "../types/index.js";

export type EnforcementResult = {
  action: "none" | "annotate" | "block";
  shouldBlockMerge: boolean;
  reason?: string;
};

export function determineEnforcement(
  scanResult: ScanResponse,
  config: RepoConfig
): EnforcementResult {
  const mode = config.enforcementMode;

  if (mode === "advisory") {
    return {
      action: "none",
      shouldBlockMerge: false,
      reason: "Advisory mode - informational only",
    };
  }

  if (mode === "warning") {
    if (scanResult.summary.totalIssues > 0) {
      return {
        action: "annotate",
        shouldBlockMerge: false,
        reason: `Found ${scanResult.summary.totalIssues} issues (warning mode)`,
      };
    }
    return {
      action: "none",
      shouldBlockMerge: false,
    };
  }

  if (mode === "blocking") {
    if (scanResult.summary.critical > 0 || scanResult.summary.high > 0) {
      return {
        action: "block",
        shouldBlockMerge: true,
        reason: `Found ${scanResult.summary.critical} critical and ${scanResult.summary.high} high severity issues`,
      };
    }
    if (scanResult.summary.totalIssues > 0) {
      return {
        action: "annotate",
        shouldBlockMerge: false,
        reason: `Found ${scanResult.summary.totalIssues} medium/low issues`,
      };
    }
    return {
      action: "none",
      shouldBlockMerge: false,
    };
  }

  return {
    action: "none",
    shouldBlockMerge: false,
  };
}

export function canOverride(
  username: string,
  config: RepoConfig
): boolean {
  if (!config.override.enabled) {
    return false;
  }

  if (config.override.approvers.length === 0) {
    return true; // Anyone can override if no specific approvers
  }

  return config.override.approvers.includes(username);
}

export function parseOverrideCommand(
  body: string
): { isOverride: boolean; justification?: string } {
  const overridePattern = /\/guardrails\s+override(?:\s+(.+))?/i;
  const match = body.match(overridePattern);

  if (!match) {
    return { isOverride: false };
  }

  return {
    isOverride: true,
    justification: match[1]?.trim(),
  };
}
