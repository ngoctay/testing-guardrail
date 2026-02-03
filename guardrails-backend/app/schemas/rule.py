from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class RuleType(str, Enum):
    REGEX = "regex"
    AST = "ast"
    AI = "ai"
    COMPOSITE = "composite"


class RuleSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleCategory(str, Enum):
    SECURITY = "security"
    STANDARDS = "standards"
    LICENSE = "license"


class RuleBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    category: RuleCategory
    severity: RuleSeverity
    enabled: bool = True
    rule_type: RuleType
    languages: List[str] = Field(default_factory=list, description="Supported languages")
    pattern: Optional[str] = Field(None, description="Regex or AST pattern")
    ai_prompt: Optional[str] = Field(None, description="AI analysis prompt")
    owasp_mapping: Optional[str] = None
    cwe_id: Optional[str] = None
    fix_suggestion: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class RuleCreate(RuleBase):
    org: Optional[str] = Field(None, description="Organization scope (None for global)")
    repo: Optional[str] = Field(None, description="Repository scope (None for org-level)")
    rule_pack: Optional[str] = Field(None, description="Rule pack name if part of a pack")


class RuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[RuleSeverity] = None
    enabled: Optional[bool] = None
    pattern: Optional[str] = None
    ai_prompt: Optional[str] = None
    fix_suggestion: Optional[str] = None
    references: Optional[List[str]] = None


class Rule(RuleBase):
    id: str
    created_at: datetime
    updated_at: datetime
    org: Optional[str] = None
    repo: Optional[str] = None
    rule_pack: Optional[str] = None

    class Config:
        from_attributes = True


class RulePack(BaseModel):
    name: str
    display_name: str
    description: str
    category: str = Field(..., description="Industry or use case (healthcare, telecom, government, default)")
    rule_count: int
    rules: List[str] = Field(default_factory=list, description="Rule IDs in this pack")
    enabled: bool = False
