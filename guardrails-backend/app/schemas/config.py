from pydantic import BaseModel, Field
from typing import List, Optional, Any
from datetime import datetime
from enum import Enum


class EnforcementMode(str, Enum):
    ADVISORY = "advisory"
    WARNING = "warning"
    BLOCKING = "blocking"


class NamingConvention(str, Enum):
    CAMEL_CASE = "camelCase"
    PASCAL_CASE = "PascalCase"
    SNAKE_CASE = "snake_case"
    SCREAMING_SNAKE_CASE = "SCREAMING_SNAKE_CASE"
    KEBAB_CASE = "kebab-case"


class NamingConfig(BaseModel):
    enabled: bool = True
    functions: dict[str, NamingConvention] = Field(default_factory=dict)
    classes: NamingConvention = NamingConvention.PASCAL_CASE
    constants: NamingConvention = NamingConvention.SCREAMING_SNAKE_CASE


class LoggingConfig(BaseModel):
    enabled: bool = True
    structured: bool = True
    required_levels: List[str] = Field(default_factory=lambda: ["error", "warn", "info"])
    forbid_console_log: bool = True


class ErrorHandlingConfig(BaseModel):
    enabled: bool = True
    async_try_catch: bool = True
    require_error_logging: bool = True
    forbid_empty_catch: bool = True


class SecurityConfig(BaseModel):
    block_threshold: str = "high"
    secrets_enabled: bool = True
    sql_injection_enabled: bool = True
    deserialization_enabled: bool = True
    command_execution_enabled: bool = True


class LicenseConfig(BaseModel):
    allowed: List[str] = Field(default_factory=lambda: ["MIT", "Apache-2.0", "BSD-3-Clause"])
    blocked: List[str] = Field(default_factory=lambda: ["GPL-3.0", "AGPL-3.0"])
    similarity_threshold: float = 0.85


class CopilotConfig(BaseModel):
    strict_mode: bool = True
    additional_checks: List[str] = Field(
        default_factory=lambda: ["license_attribution", "security_review", "code_similarity"]
    )


class OverrideConfig(BaseModel):
    enabled: bool = True
    approvers: List[str] = Field(default_factory=list)


class RepoConfigBase(BaseModel):
    enforcement_mode: EnforcementMode = EnforcementMode.WARNING
    enabled_rule_packs: List[str] = Field(
        default_factory=lambda: ["default-security", "enterprise-standards"]
    )
    custom_rules: List[str] = Field(default_factory=list)
    override: OverrideConfig = Field(default_factory=OverrideConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    naming: NamingConfig = Field(default_factory=NamingConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    error_handling: ErrorHandlingConfig = Field(default_factory=ErrorHandlingConfig)
    license: LicenseConfig = Field(default_factory=LicenseConfig)
    copilot: CopilotConfig = Field(default_factory=CopilotConfig)
    include_patterns: List[str] = Field(default_factory=lambda: ["src/**/*", "lib/**/*"])
    exclude_patterns: List[str] = Field(
        default_factory=lambda: ["node_modules/**", "dist/**", "build/**", "*.min.js"]
    )
    extra_data: Optional[dict[str, Any]] = None


class RepoConfigUpdate(BaseModel):
    enforcement_mode: Optional[EnforcementMode] = None
    enabled_rule_packs: Optional[List[str]] = None
    custom_rules: Optional[List[str]] = None
    override: Optional[OverrideConfig] = None
    security: Optional[SecurityConfig] = None
    naming: Optional[NamingConfig] = None
    logging: Optional[LoggingConfig] = None
    error_handling: Optional[ErrorHandlingConfig] = None
    license: Optional[LicenseConfig] = None
    copilot: Optional[CopilotConfig] = None
    include_patterns: Optional[List[str]] = None
    exclude_patterns: Optional[List[str]] = None
    extra_data: Optional[dict[str, Any]] = None


class RepoConfig(RepoConfigBase):
    id: Optional[str] = None
    org: str
    repo: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
