import chalk from "chalk";
import { ScanResult, Violation } from "./api-client.js";

// Valid severity levels - used for type safety and validation
const VALID_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
type Severity = typeof VALID_SEVERITIES[number];

function isValidSeverity(value: string): value is Severity {
  return VALID_SEVERITIES.includes(value as Severity);
}

const SEVERITY_COLORS: Record<Severity, typeof chalk> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "\u{1F534}",
  high: "\u{1F7E0}",
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
  info: "\u{2139}\u{FE0F}",
};

export function formatResults(results: ScanResult[], verbose: boolean): string {
  const lines: string[] = [];

  for (const result of results) {
    if (result.violations.length === 0) {
      continue;
    }

    // Group violations by severity
    const bySeverity = groupBy(result.violations, (v) => v.severity);

    for (const severity of VALID_SEVERITIES) {
      const violations = Object.prototype.hasOwnProperty.call(bySeverity, severity)
        ? bySeverity[severity]
        : [];
      if (violations.length === 0) continue;

      for (const violation of violations) {
        lines.push(formatViolation(violation, verbose));
        lines.push("");
      }
    }
  }

  return lines.join("\n");
}

function formatViolation(violation: Violation, verbose: boolean): string {
  const lines: string[] = [];
  // Validate severity to prevent object injection
  const severity = isValidSeverity(violation.severity) ? violation.severity : "info";
  const severityColor = SEVERITY_COLORS[severity];
  const icon = SEVERITY_ICONS[severity];

  // Header
  lines.push(
    `${icon} ${severityColor(violation.severity.toUpperCase())} ${chalk.bold(violation.title)}`
  );

  // Location
  lines.push(
    chalk.dim(`   ${violation.filePath}:${violation.lineStart}`)
  );

  // Rule info
  const ruleInfo: string[] = [`Rule: ${violation.ruleId}`];
  if (violation.owaspMapping) {
    ruleInfo.push(`OWASP: ${violation.owaspMapping}`);
  }
  if (violation.cweId) {
    ruleInfo.push(`CWE: ${violation.cweId}`);
  }
  lines.push(chalk.dim(`   ${ruleInfo.join(" | ")}`));

  // Description
  if (verbose && violation.description) {
    lines.push("");
    lines.push(chalk.white(`   ${violation.description}`));
  }

  // Code snippet
  if (violation.codeSnippet) {
    lines.push("");
    lines.push(chalk.dim("   " + "-".repeat(60)));
    const snippetLines = violation.codeSnippet.split("\n");
    for (const line of snippetLines) {
      lines.push(chalk.cyan(`   ${line}`));
    }
    lines.push(chalk.dim("   " + "-".repeat(60)));
  }

  // Explanation
  if (verbose && violation.explanation) {
    lines.push("");
    lines.push(chalk.white("   Why: ") + chalk.dim(violation.explanation));
  }

  // Suggested fix
  if (violation.suggestedFix) {
    lines.push("");
    lines.push(chalk.green("   Suggested fix:"));
    const fixLines = violation.suggestedFix.split("\n");
    for (const line of fixLines.slice(0, verbose ? undefined : 5)) {
      lines.push(chalk.green(`   ${line}`));
    }
    if (!verbose && fixLines.length > 5) {
      lines.push(chalk.dim(`   ... (${fixLines.length - 5} more lines)`));
    }
  }

  return lines.join("\n");
}

export function formatResultsJson(results: ScanResult[]): string {
  const output = {
    summary: {
      totalFiles: results.length,
      totalIssues: results.reduce((sum, r) => sum + r.summary.totalIssues, 0),
      critical: results.reduce((sum, r) => sum + r.summary.critical, 0),
      high: results.reduce((sum, r) => sum + r.summary.high, 0),
      medium: results.reduce((sum, r) => sum + r.summary.medium, 0),
      low: results.reduce((sum, r) => sum + r.summary.low, 0),
      info: results.reduce((sum, r) => sum + r.summary.info, 0),
    },
    results,
  };

  return JSON.stringify(output, null, 2);
}

function groupBy<T>(array: T[], keyFn: (item: T) => string): Record<string, T[]> {
  return array.reduce(
    (groups, item) => {
      const key = keyFn(item);
      if (!groups[key]) {
        groups[key] = [];
      }
      groups[key].push(item);
      return groups;
    },
    {} as Record<string, T[]>
  );
}
