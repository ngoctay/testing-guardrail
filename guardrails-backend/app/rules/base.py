from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
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


@dataclass
class RuleResult:
    """Result from running a rule check."""

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
    explanation: str = ""
    suggested_fix: Optional[str] = None
    references: list[str] = field(default_factory=list)


class BaseRule(ABC):
    """Abstract base class for all rules."""

    # Rule metadata - must be defined by subclasses
    rule_id: str
    name: str
    description: str
    severity: Severity
    category: Category
    languages: list[str]  # Empty list means all languages
    owasp_mapping: Optional[str] = None
    cwe_id: Optional[str] = None
    references: list[str] = []

    @abstractmethod
    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        """
        Check code against this rule.

        Args:
            code: The source code to check
            file_path: Path to the file being checked
            language: Programming language of the code

        Returns:
            List of RuleResult for each violation found
        """
        pass

    def supports_language(self, language: str) -> bool:
        """Check if this rule supports the given language."""
        if not self.languages:
            return True  # Empty list means all languages
        return language.lower() in [lang.lower() for lang in self.languages]

    def _create_result(
        self,
        file_path: str,
        line_start: int,
        line_end: int,
        code_snippet: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        explanation: str = "",
        suggested_fix: Optional[str] = None,
    ) -> RuleResult:
        """Helper to create a RuleResult with default values from the rule."""
        return RuleResult(
            rule_id=self.rule_id,
            severity=self.severity,
            category=self.category,
            title=title or self.name,
            description=description or self.description,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=code_snippet,
            owasp_mapping=self.owasp_mapping,
            cwe_id=self.cwe_id,
            explanation=explanation,
            suggested_fix=suggested_fix,
            references=self.references.copy(),
        )
