from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class LicenseStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REVIEW = "review"
    UNKNOWN = "unknown"


class FileContent(BaseModel):
    path: str
    content: str


class LicenseRequest(BaseModel):
    files: List[FileContent] = Field(..., description="Files to check for license compliance")
    allowed_licenses: List[str] = Field(
        default_factory=lambda: ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]
    )
    blocked_licenses: List[str] = Field(
        default_factory=lambda: ["GPL-2.0", "GPL-3.0", "AGPL-3.0"]
    )


class DetectedLicense(BaseModel):
    file_path: str
    license_id: str = Field(..., description="SPDX license identifier")
    license_name: str
    status: LicenseStatus
    confidence: float = Field(..., ge=0, le=1)
    source: str = Field(..., description="How license was detected (header, file, package.json, etc.)")


class LicenseResponse(BaseModel):
    check_id: str
    status: str = Field(..., description="compliant | non_compliant | review_required")
    total_files: int
    compliant_count: int
    non_compliant_count: int
    review_count: int
    detected_licenses: List[DetectedLicense] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class SimilarityRequest(BaseModel):
    code: str = Field(..., description="Code to check for similarity")
    file_path: str
    language: str
    threshold: float = Field(default=0.85, ge=0, le=1, description="Similarity threshold")


class SimilarityMatch(BaseModel):
    source: str = Field(..., description="Source of similar code (URL, project name)")
    similarity_score: float = Field(..., ge=0, le=1)
    matched_lines: List[int] = Field(default_factory=list)
    license: Optional[str] = None
    risk_level: str = Field(..., description="low | medium | high")


class SimilarityResponse(BaseModel):
    check_id: str
    file_path: str
    has_similar_code: bool
    matches: List[SimilarityMatch] = Field(default_factory=list)
    ip_risk_assessment: str = Field(..., description="Assessment of IP risk")
    recommendations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
