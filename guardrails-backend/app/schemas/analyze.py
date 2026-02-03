from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum

from app.schemas.scan import ScanContext, Violation


class AnalysisType(str, Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"


class AnalyzeRequest(BaseModel):
    code: str = Field(..., description="Code content to analyze")
    file_path: str = Field(..., description="File path for context")
    language: str = Field(..., description="Programming language")
    analysis_types: List[AnalysisType] = Field(
        default_factory=lambda: [AnalysisType.SECURITY, AnalysisType.PERFORMANCE, AnalysisType.MAINTAINABILITY]
    )
    context: Optional[ScanContext] = None


class AnalysisResult(BaseModel):
    type: AnalysisType
    score: float = Field(..., ge=0, le=100, description="Quality score 0-100")
    findings: List[dict] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    analysis_id: str
    file_path: str
    language: str
    results: List[AnalysisResult]
    overall_score: float = Field(..., ge=0, le=100)
    violations: List[Violation] = Field(default_factory=list)
    ai_model_used: str
    tokens_used: int
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FixRequest(BaseModel):
    code: str = Field(..., description="Original code with issue")
    file_path: str
    language: str
    violation_id: str = Field(..., description="ID of the violation to fix")
    violation_description: str = Field(..., description="Description of the issue")
    context: Optional[ScanContext] = None


class CodeFix(BaseModel):
    original_code: str
    fixed_code: str
    diff: str
    explanation: str = Field(..., description="Explanation of the fix")
    confidence: float = Field(..., ge=0, le=1, description="Confidence in the fix")


class FixResponse(BaseModel):
    fix_id: str
    violation_id: str
    fixes: List[CodeFix] = Field(default_factory=list, description="Multiple fix options")
    recommended_fix_index: int = 0
    ai_model_used: str
    tokens_used: int
    created_at: datetime = Field(default_factory=datetime.utcnow)
