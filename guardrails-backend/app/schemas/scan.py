from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    STANDARDS = "standards"
    LICENSE = "license"


class EnforcementMode(str, Enum):
    ADVISORY = "advisory"
    WARNING = "warning"
    BLOCKING = "blocking"


class ScanContext(BaseModel):
    org: str
    repo: str
    pr_number: Optional[int] = None
    commit_sha: Optional[str] = None
    author: Optional[str] = None


class ScanOptions(BaseModel):
    enable_ai: bool = True
    enforcement_mode: EnforcementMode = EnforcementMode.WARNING
    rule_packs: List[str] = Field(default_factory=lambda: ["default-security", "enterprise-standards"])
    custom_rules: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    code: str = Field(..., description="Code content to scan")
    file_path: str = Field(..., description="File path for context")
    language: str = Field(..., description="Programming language")
    diff_only: bool = Field(default=False, description="Scan only diff lines")
    context: ScanContext
    options: ScanOptions = Field(default_factory=ScanOptions)


class Violation(BaseModel):
    id: str
    rule_id: str
    severity: Severity
    category: Category
    title: str
    description: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    owasp_mapping: Optional[str] = None
    cwe_id: Optional[str] = None
    is_ai_generated: bool = False
    explanation: str = Field(..., description="AI-generated explanation of the issue")
    suggested_fix: Optional[str] = Field(None, description="AI-generated fix suggestion")
    fix_diff: Optional[str] = Field(None, description="Diff of the suggested fix")
    references: List[str] = Field(default_factory=list)


class ScanSummary(BaseModel):
    total_issues: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class CopilotAnalysis(BaseModel):
    detected_ai_code: bool = False
    ai_code_percentage: float = 0.0
    ai_code_lines: List[int] = Field(default_factory=list)


class ScanResponse(BaseModel):
    scan_id: str
    status: str = Field(..., description="clean | violations_found | error")
    summary: ScanSummary
    violations: List[Violation] = Field(default_factory=list)
    copilot_analysis: CopilotAnalysis = Field(default_factory=CopilotAnalysis)
    enforcement_action: str = Field(..., description="none | annotate | block")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class SecurityScanResponse(BaseModel):
    scan_id: str
    status: str
    summary: ScanSummary
    violations: List[Violation] = Field(default_factory=list)
    owasp_coverage: dict = Field(default_factory=dict)


class StandardsScanResponse(BaseModel):
    scan_id: str
    status: str
    summary: ScanSummary
    violations: List[Violation] = Field(default_factory=list)
    standards_compliance: dict = Field(default_factory=dict)
