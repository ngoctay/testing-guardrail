import type { ScanRequest, ScanResponse, RepoConfig } from "../types/index.js";

const BACKEND_URL = process.env.BACKEND_API_URL || "http://localhost:8000";
const BACKEND_API_KEY = process.env.BACKEND_API_KEY || "";

// Whitelist of allowed API endpoints to prevent SSRF
const ALLOWED_ENDPOINTS = [
  "/health",
  "/api/v1/scan",
  "/api/v1/config/",
] as const;

function isAllowedEndpoint(endpoint: string): boolean {
  return ALLOWED_ENDPOINTS.some(allowed =>
    endpoint === allowed || endpoint.startsWith(allowed)
  );
}

interface ApiError {
  detail: string;
  status: number;
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  // Validate endpoint against whitelist to prevent SSRF
  if (!isAllowedEndpoint(endpoint)) {
    throw new Error(`Invalid API endpoint: ${endpoint}`);
  }

  // Construct URL safely using only the trusted BACKEND_URL
  const baseUrl = new URL(BACKEND_URL);
  const url = new URL(endpoint, baseUrl).toString();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  if (BACKEND_API_KEY) {
    headers["X-API-Key"] = BACKEND_API_KEY;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error: ApiError = {
      detail: await response.text(),
      status: response.status,
    };
    throw new Error(`API Error ${error.status}: ${error.detail}`);
  }

  return response.json() as Promise<T>;
}

interface BackendRepoConfig {
  id?: string;
  org: string;
  repo?: string;
  enforcement_mode: string;
  enabled_rule_packs: string[];
  custom_rules?: string[];
  override?: {
    enabled: boolean;
    approvers: string[];
  };
  created_at?: string;
  updated_at?: string;
}

interface BackendScanResponse {
  scan_id: string;
  status: string;
  summary: {
    total_issues: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  violations: Array<{
    id: string;
    rule_id: string;
    severity: string;
    category: string;
    title: string;
    description: string;
    file_path: string;
    line_start: number;
    line_end: number;
    code_snippet: string;
    owasp_mapping?: string;
    cwe_id?: string;
    is_ai_generated: boolean;
    explanation: string;
    suggested_fix?: string;
    fix_diff?: string;
    references: string[];
  }>;
  copilot_analysis: {
    detected_ai_code: boolean;
    ai_code_percentage: number;
    ai_code_lines: number[];
  };
  enforcement_action: string;
  created_at: string;
}

export async function scanCode(request: ScanRequest): Promise<ScanResponse> {
  console.log(`[scanCode] Scanning file: ${request.filePath}`);
  const response = await apiRequest<BackendScanResponse>("/api/v1/scan", {
    method: "POST",
    body: JSON.stringify({
      code: request.code,
      file_path: request.filePath,
      language: request.language,
      diff_only: request.diffOnly,
      context: {
        org: request.context.org,
        repo: request.context.repo,
        pr_number: request.context.prNumber,
        commit_sha: request.context.commitSha,
        author: request.context.author,
      },
      options: {
        enable_ai: request.options.enableAi,
        enforcement_mode: request.options.enforcementMode,
        rule_packs: request.options.rulePacks,
        custom_rules: request.options.customRules,
      },
    }),
  });

  console.log("[scanCode] Raw response for file:", request.filePath, JSON.stringify({
    scan_id: response.scan_id,
    status: response.status,
    summary: response.summary,
    violations_count: response.violations?.length ?? 'undefined',
  }));

  // Transform snake_case response to camelCase
  return {
    scanId: response.scan_id,
    status: response.status as ScanResponse["status"],
    summary: {
      totalIssues: response.summary.total_issues,
      critical: response.summary.critical,
      high: response.summary.high,
      medium: response.summary.medium,
      low: response.summary.low,
      info: response.summary.info,
    },
    violations: response.violations.map((v) => ({
      id: v.id,
      ruleId: v.rule_id,
      severity: v.severity.toLowerCase() as "critical" | "high" | "medium" | "low" | "info",
      category: v.category.toLowerCase() as "security" | "standards" | "license",
      title: v.title,
      description: v.description,
      filePath: v.file_path,
      lineStart: v.line_start,
      lineEnd: v.line_end,
      codeSnippet: v.code_snippet,
      owaspMapping: v.owasp_mapping,
      cweId: v.cwe_id,
      isAiGenerated: v.is_ai_generated,
      explanation: v.explanation,
      suggestedFix: v.suggested_fix,
      fixDiff: v.fix_diff,
      references: v.references,
    })),
    copilotAnalysis: {
      detectedAiCode: response.copilot_analysis.detected_ai_code,
      aiCodePercentage: response.copilot_analysis.ai_code_percentage,
      aiCodeLines: response.copilot_analysis.ai_code_lines,
    },
    enforcementAction: response.enforcement_action as ScanResponse["enforcementAction"],
    createdAt: response.created_at,
  };
}

export async function getRepoConfig(
  org: string,
  repo: string
): Promise<RepoConfig> {
  const response = await apiRequest<BackendRepoConfig>(`/api/v1/config/${org}/${repo}`);

  console.log("[getRepoConfig] Raw response for repo:", org, "/", repo, JSON.stringify(response));

  // Transform snake_case response to camelCase
  return {
    enforcementMode: response.enforcement_mode as RepoConfig["enforcementMode"],
    enabledRulePacks: response.enabled_rule_packs,
    override: response.override ?? { enabled: false, approvers: [] },
  };
}

export async function healthCheck(): Promise<{ status: string }> {
  return apiRequest<{ status: string }>("/health");
}
