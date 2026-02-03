import type { ScanResponse, Violation } from "../types/index.js";

/**
 * Escapes HTML special characters to prevent XSS.
 * Used when inserting user-controlled data into HTML templates.
 */
function escapeHtml(text: string): string {
  const htmlEscapes: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  };
  return text.replace(/[&<>"']/g, (char) => htmlEscapes[char]);
}

const SEVERITY_EMOJI: Record<string, string> = {
  critical: "\u{1F534}",
  high: "\u{1F7E7}",  // 🟧 Orange square - more compatible than orange circle
  medium: "\u{1F7E1}",
  low: "\u{1F535}",
  info: "\u{2139}\u{FE0F}",
};

// Valid enforcement actions for type safety
const VALID_ENFORCEMENT_ACTIONS = ["none", "annotate", "block"] as const;
type EnforcementAction = typeof VALID_ENFORCEMENT_ACTIONS[number];

function isValidEnforcementAction(value: string): value is EnforcementAction {
  return VALID_ENFORCEMENT_ACTIONS.includes(value as EnforcementAction);
}

const ENFORCEMENT_ACTION_TEXT: Record<EnforcementAction, string> = {
  none: "\u{2705} No issues found",
  annotate: "\u{26A0}\u{FE0F} Warning (merge allowed with issues)",
  block: "\u{1F6AB} Blocked (critical/high issues must be resolved)",
};

export function formatPrComment(
  result: ScanResponse,
  overrideAllowed: boolean
): string {
  const lines: string[] = [];

  // Header
  lines.push("## \u{1F6E1}\u{FE0F} Guardrails Security & Compliance Report\n");
  lines.push(`**Scan ID:** \`${result.scanId}\``);
  lines.push(`**Scanned at:** ${result.createdAt}\n`);
  lines.push("---\n");

  // Summary
  lines.push("### \u{1F4CA} Summary\n");
  lines.push("| Severity | Count |");
  lines.push("|----------|-------|");
  lines.push(
    `| ${SEVERITY_EMOJI.critical} Critical | ${result.summary.critical} |`
  );
  lines.push(`| ${SEVERITY_EMOJI.high} High | ${result.summary.high} |`);
  lines.push(`| ${SEVERITY_EMOJI.medium} Medium | ${result.summary.medium} |`);
  lines.push(`| ${SEVERITY_EMOJI.low} Low | ${result.summary.low} |`);
  lines.push(`| ${SEVERITY_EMOJI.info} Info | ${result.summary.info} |\n`);

  // Validate enforcement action to prevent object injection
  const enforcementAction = isValidEnforcementAction(result.enforcementAction)
    ? result.enforcementAction
    : "none";
  lines.push(
    `**Enforcement Action:** ${ENFORCEMENT_ACTION_TEXT[enforcementAction]}\n`
  );

  // Copilot Analysis (informational)
  if (result.copilotAnalysis.aiCodePercentage > 0) {
    lines.push("---\n");
    lines.push("### 🤖 AI-Generated Code Analysis\n");
    lines.push(
      `This PR contains an estimated **${(result.copilotAnalysis.aiCodePercentage * 100).toFixed(1)}%** of code that appears to be AI-generated (e.g., GitHub Copilot).`
    );
    if (result.copilotAnalysis.aiCodeLines.length > 0) {
      lines.push(
        `\n\n<details><summary>View detected lines</summary>\n\nLines: ${result.copilotAnalysis.aiCodeLines.slice(0, 20).join(", ")}${result.copilotAnalysis.aiCodeLines.length > 20 ? "..." : ""}\n</details>`
      );
    }
    lines.push("\n");
  }

  // Violations by severity
  if (result.violations.length > 0) {
    lines.push("---\n");

    // Group violations by severity
    const criticalViolations = result.violations.filter(
      (v) => v.severity === "critical"
    );
    const highViolations = result.violations.filter(
      (v) => v.severity === "high"
    );
    const mediumViolations = result.violations.filter(
      (v) => v.severity === "medium"
    );
    const lowViolations = result.violations.filter((v) => v.severity === "low");
    const infoViolations = result.violations.filter(
      (v) => v.severity === "info"
    );

    if (criticalViolations.length > 0) {
      lines.push(`### ${SEVERITY_EMOJI.critical} Critical Issues\n`);
      lines.push(...criticalViolations.map(formatViolation));
      lines.push(""); // Blank line after section
    }

    if (highViolations.length > 0) {
      lines.push(`### ${SEVERITY_EMOJI.high} High Issues\n`);
      lines.push(...highViolations.map(formatViolation));
      lines.push(""); // Blank line after section
    }

    if (mediumViolations.length > 0) {
      lines.push(`### ${SEVERITY_EMOJI.medium} Medium Issues\n`);
      lines.push(...mediumViolations.slice(0, 5).map(formatViolation));
      if (mediumViolations.length > 5) {
        lines.push(
          `<details><summary>Show ${mediumViolations.length - 5} more medium issues</summary>\n`
        );
        lines.push(...mediumViolations.slice(5).map(formatViolation));
        lines.push("</details>\n");
      }
    }

    if (lowViolations.length > 0) {
      lines.push(
        `<details><summary>${SEVERITY_EMOJI.low} Low Issues (${lowViolations.length})</summary>\n`
      );
      lines.push(...lowViolations.map(formatViolation));
      lines.push("</details>\n");
    }

    if (infoViolations.length > 0) {
      lines.push(
        `<details><summary>${SEVERITY_EMOJI.info} Info (${infoViolations.length})</summary>\n`
      );
      lines.push(...infoViolations.map(formatViolation));
      lines.push("</details>\n");
    }
  }

  // Actions
  lines.push("---\n");
  lines.push("### \u{1F504} Actions\n");

  if (result.summary.critical > 0 || result.summary.high > 0) {
    lines.push("- [ ] Fix critical and high severity issues before merge");
  }
  if (result.summary.medium > 0) {
    lines.push("- [ ] Review medium severity issues");
  }

  if (result.enforcementAction === "block" && overrideAllowed) {
    lines.push(
      "\n**Override:** To override blocking (requires approval), comment `/guardrails override` with justification.\n"
    );
  }

  // Footer
  lines.push("---\n");
  lines.push(
    "<sub>Powered by Topcoder Enterprise Guardrails AI</sub>"
  );

  return lines.join("\n");
}

function formatViolation(violation: Violation): string {
  const lines: string[] = [];

  lines.push("<details>");
  lines.push(
    `<summary><b>${escapeHtml(violation.title)}</b> - <code>${escapeHtml(violation.filePath)}:${violation.lineStart}</code></summary>\n`
  );

  // Rule info
  const ruleInfo: string[] = [`**Rule:** \`${violation.ruleId}\``];
  if (violation.owaspMapping) {
    ruleInfo.push(`**OWASP:** ${violation.owaspMapping}`);
  }
  if (violation.cweId) {
    ruleInfo.push(`**CWE:** ${violation.cweId}`);
  }
  lines.push(ruleInfo.join(" | ") + "\n");

  // Code snippet
  if (violation.codeSnippet) {
    const lang = getLanguageFromFile(violation.filePath);
    lines.push("```" + lang);
    lines.push(`// Line ${violation.lineStart}-${violation.lineEnd}`);
    lines.push(violation.codeSnippet);
    lines.push("```\n");
  }

  // Explanation
  lines.push("**Why this is an issue:**");
  lines.push(violation.explanation + "\n");

  // AI-generated marker
  if (violation.isAiGenerated) {
    lines.push(
      "**\u{1F916} AI-Generated Code Detected:** Yes (stricter review applied)\n"
    );
  }

  // Suggested fix
  if (violation.suggestedFix) {
    lines.push("**Suggested Fix:**");
    // Check if the suggested fix already contains code blocks
    if (violation.suggestedFix.includes("```")) {
      // Already has code blocks, use as-is
      lines.push(violation.suggestedFix + "\n");
    } else {
      // Wrap in code block
      const lang = getLanguageFromFile(violation.filePath);
      lines.push("```" + lang);
      lines.push(violation.suggestedFix);
      lines.push("```\n");
    }
  }

  // References
  if (violation.references.length > 0) {
    lines.push("**References:**");
    violation.references.forEach((ref) => {
      lines.push(`- ${ref}`);
    });
    lines.push("");
  }

  lines.push("</details>\n");

  return lines.join("\n");
}

function getLanguageFromFile(filePath: string): string {
  const ext = filePath.split(".").pop()?.toLowerCase() || "";
  const langMap: Record<string, string> = {
    ts: "typescript",
    tsx: "typescript",
    js: "javascript",
    jsx: "javascript",
    py: "python",
    java: "java",
    go: "go",
    rb: "ruby",
    rs: "rust",
    cpp: "cpp",
    c: "c",
    cs: "csharp",
    php: "php",
    swift: "swift",
    kt: "kotlin",
  };
  return langMap[ext] || ext;
}

export function formatInlineComment(violation: Violation): string {
  const lines: string[] = [];

  lines.push(`\u{26A0}\u{FE0F} **${escapeHtml(violation.title)}**\n`);
  lines.push(`**Severity:** ${violation.severity.toUpperCase()}`);

  if (violation.owaspMapping) {
    lines.push(`**OWASP:** ${violation.owaspMapping}`);
  }

  lines.push(`\n${violation.explanation}`);

  if (violation.suggestedFix) {
    lines.push("\n**Suggested Fix:**");
    const lang = getLanguageFromFile(violation.filePath);
    lines.push("```" + lang);
    lines.push(violation.suggestedFix);
    lines.push("```");
  }

  return lines.join("\n");
}
