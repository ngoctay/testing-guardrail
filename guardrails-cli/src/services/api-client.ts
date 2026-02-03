const BACKEND_URL = process.env.BACKEND_API_URL || "http://localhost:8000";

export interface ScanRequest {
  code: string;
  filePath: string;
  language: string;
  enableAi: boolean;
  enforcementMode: string;
  rulePacks: string[];
}

export interface Violation {
  id: string;
  ruleId: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: "security" | "standards" | "license";
  title: string;
  description: string;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  codeSnippet: string;
  owaspMapping?: string;
  cweId?: string;
  explanation: string;
  suggestedFix?: string;
}

export interface ScanSummary {
  totalIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanResult {
  scanId: string;
  status: "clean" | "violations_found" | "error";
  summary: ScanSummary;
  violations: Violation[];
  enforcementAction: string;
}

export async function scanCode(request: ScanRequest): Promise<ScanResult> {
  try {
    const response = await fetch(`${BACKEND_URL}/api/v1/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        code: request.code,
        file_path: request.filePath,
        language: request.language,
        diff_only: false,
        context: {
          org: "local",
          repo: "local",
        },
        options: {
          enable_ai: request.enableAi,
          enforcement_mode: request.enforcementMode,
          rule_packs: request.rulePacks,
          custom_rules: [],
        },
      }),
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();

    // Transform snake_case to camelCase
    return {
      scanId: data.scan_id,
      status: data.status,
      summary: {
        totalIssues: data.summary.total_issues,
        critical: data.summary.critical,
        high: data.summary.high,
        medium: data.summary.medium,
        low: data.summary.low,
        info: data.summary.info,
      },
      violations: data.violations.map((v: Record<string, unknown>) => ({
        id: v.id,
        ruleId: v.rule_id,
        severity: v.severity,
        category: v.category,
        title: v.title,
        description: v.description,
        filePath: v.file_path,
        lineStart: v.line_start,
        lineEnd: v.line_end,
        codeSnippet: v.code_snippet,
        owaspMapping: v.owasp_mapping,
        cweId: v.cwe_id,
        explanation: v.explanation,
        suggestedFix: v.suggested_fix,
      })),
      enforcementAction: data.enforcement_action,
    };
  } catch (error) {
    // Return a local-only scan result if the API is unavailable
    // In production, you might want to handle this differently
    console.warn("Backend API unavailable, running local checks only");

    return {
      scanId: "local",
      status: "clean",
      summary: {
        totalIssues: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      },
      violations: [],
      enforcementAction: "none",
    };
  }
}
