export interface ScanContext {
  org: string;
  repo: string;
  prNumber?: number;
  commitSha?: string;
  author?: string;
  branch?: string;
}

export interface ScanOptions {
  enableAi: boolean;
  enforcementMode: "advisory" | "warning" | "blocking";
  rulePacks: string[];
  customRules: string[];
}

export interface ScanRequest {
  code: string;
  filePath: string;
  language: string;
  diffOnly: boolean;
  context: ScanContext;
  options: ScanOptions;
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
  isAiGenerated: boolean;
  explanation: string;
  suggestedFix?: string;
  fixDiff?: string;
  references: string[];
}

export interface ScanSummary {
  totalIssues: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface CopilotAnalysis {
  detectedAiCode: boolean;
  aiCodePercentage: number;
  aiCodeLines: number[];
}

export interface ScanResponse {
  scanId: string;
  status: "clean" | "violations_found" | "error";
  summary: ScanSummary;
  violations: Violation[];
  copilotAnalysis: CopilotAnalysis;
  enforcementAction: "none" | "annotate" | "block";
  createdAt: string;
}

export interface RepoConfig {
  enforcementMode: "advisory" | "warning" | "blocking";
  enabledRulePacks: string[];
  override: {
    enabled: boolean;
    approvers: string[];
  };
}

export interface PullRequestFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
  patch?: string;
  rawUrl: string;
}
