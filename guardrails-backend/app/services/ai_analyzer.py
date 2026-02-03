import uuid
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.analyze import (
    AnalyzeRequest,
    AnalyzeResponse,
    FixRequest,
    FixResponse,
    AnalysisResult,
    AnalysisType,
    CodeFix,
)
from app.schemas.scan import Violation, Severity, Category
from app.core.ai_client import AIClient


class AIAnalyzerService:
    """AI-powered code analysis service."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_client = AIClient()

    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        """Perform AI-powered deep code analysis."""
        analysis_id = str(uuid.uuid4())
        results: list[AnalysisResult] = []
        violations: list[Violation] = []
        total_tokens = 0

        for analysis_type in request.analysis_types:
            if analysis_type == AnalysisType.SECURITY:
                security_result = await self.ai_client.analyze_security(
                    code=request.code,
                    file_path=request.file_path,
                    language=request.language,
                )
                total_tokens += security_result.get("tokens_used", 0)

                ai_violations = security_result.get("violations", [])
                score = 100 - (len(ai_violations) * 10)  # Simple scoring
                score = max(0, min(100, score))

                results.append(AnalysisResult(
                    type=analysis_type,
                    score=score,
                    findings=[{"type": "security", "count": len(ai_violations)}],
                    recommendations=self._extract_recommendations(ai_violations),
                ))

                for v in ai_violations:
                    violations.append(self._convert_to_violation(v, Category.SECURITY, request.file_path))

            elif analysis_type == AnalysisType.PERFORMANCE:
                # Performance analysis via AI
                perf_result = await self._analyze_performance(
                    request.code,
                    request.file_path,
                    request.language,
                )
                total_tokens += perf_result.get("tokens_used", 0)

                results.append(AnalysisResult(
                    type=analysis_type,
                    score=perf_result.get("score", 80),
                    findings=perf_result.get("findings", []),
                    recommendations=perf_result.get("recommendations", []),
                ))

            elif analysis_type == AnalysisType.MAINTAINABILITY:
                standards_result = await self.ai_client.analyze_standards(
                    code=request.code,
                    file_path=request.file_path,
                    language=request.language,
                )
                total_tokens += standards_result.get("tokens_used", 0)

                ai_violations = standards_result.get("violations", [])
                score = 100 - (len(ai_violations) * 5)
                score = max(0, min(100, score))

                results.append(AnalysisResult(
                    type=analysis_type,
                    score=score,
                    findings=[{"type": "standards", "count": len(ai_violations)}],
                    recommendations=self._extract_recommendations(ai_violations),
                ))

                for v in ai_violations:
                    violations.append(self._convert_to_violation(v, Category.STANDARDS, request.file_path))

        # Calculate overall score
        overall_score = sum(r.score for r in results) / len(results) if results else 0

        return AnalyzeResponse(
            analysis_id=analysis_id,
            file_path=request.file_path,
            language=request.language,
            results=results,
            overall_score=overall_score,
            violations=violations,
            ai_model_used=self.ai_client.model,
            tokens_used=total_tokens,
            created_at=datetime.utcnow(),
        )

    async def suggest_fix(self, request: FixRequest) -> FixResponse:
        """Generate fix suggestions for a violation."""
        fix_id = str(uuid.uuid4())

        fix_result = await self.ai_client.suggest_fix(
            code=request.code,
            violation={
                "title": request.violation_description,
                "line_start": 1,
            },
            language=request.language,
        )

        fixes = []
        if fix_result.get("fixed_code"):
            fixes.append(CodeFix(
                original_code=request.code,
                fixed_code=fix_result.get("fixed_code", ""),
                diff=fix_result.get("diff", ""),
                explanation=fix_result.get("explanation", ""),
                confidence=fix_result.get("confidence", 0.8),
            ))

        return FixResponse(
            fix_id=fix_id,
            violation_id=request.violation_id,
            fixes=fixes,
            recommended_fix_index=0,
            ai_model_used=self.ai_client.model,
            tokens_used=fix_result.get("tokens_used", 0),
            created_at=datetime.utcnow(),
        )

    async def _analyze_performance(
        self,
        code: str,
        file_path: str,
        language: str,
    ) -> dict:
        """Analyze code for performance issues using AI."""
        # This would call a specialized performance analysis prompt
        # For now, return a placeholder
        return {
            "score": 85,
            "findings": [],
            "recommendations": [
                "Consider using async/await for I/O operations",
                "Review loop efficiency for large data sets",
            ],
            "tokens_used": 0,
        }

    def _extract_recommendations(self, violations: list[dict]) -> list[str]:
        """Extract recommendations from violations."""
        recommendations = []
        for v in violations:
            if v.get("suggested_fix"):
                recommendations.append(f"Fix: {v.get('title', 'Issue')}")
        return recommendations[:5]  # Limit to 5 recommendations

    def _convert_to_violation(
        self,
        ai_violation: dict,
        category: Category,
        file_path: str,
    ) -> Violation:
        """Convert AI violation dict to Violation schema."""
        severity_str = ai_violation.get("severity", "medium").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.MEDIUM

        return Violation(
            id=str(uuid.uuid4()),
            rule_id=f"AI-{category.value.upper()}-001",
            severity=severity,
            category=category,
            title=ai_violation.get("title", "Unknown Issue"),
            description=ai_violation.get("description", ""),
            file_path=file_path,
            line_start=ai_violation.get("line_start", 1),
            line_end=ai_violation.get("line_end", 1),
            code_snippet=ai_violation.get("code_snippet", ""),
            owasp_mapping=ai_violation.get("owasp_mapping"),
            cwe_id=ai_violation.get("cwe_id"),
            explanation=ai_violation.get("explanation", ""),
            suggested_fix=ai_violation.get("suggested_fix"),
        )
