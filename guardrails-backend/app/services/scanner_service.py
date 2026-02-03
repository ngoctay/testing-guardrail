import uuid
import asyncio
from datetime import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.scan import (
    ScanRequest,
    ScanResponse,
    SecurityScanResponse,
    StandardsScanResponse,
    ScanSummary,
    CopilotAnalysis,
    Violation,
    Severity,
    Category,
)
from app.core.ai_client import AIClient
from app.models.scan_result import ScanResultModel
from app.models.violation import ViolationModel
from app.models.audit_log import AuditLogModel
from app.rules.engine import RuleEngine
from app.rules.base import RuleResult, Category as RuleCategory, Severity as RuleSeverity


class ScannerService:
    """Main scanner service that orchestrates all scanning operations."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_client = AIClient()
        self.rule_engine = RuleEngine()

    async def scan(self, request: ScanRequest) -> ScanResponse:
        """Perform a full code scan including security, standards, and AI analysis."""
        scan_id = str(uuid.uuid4())
        violations: list[Violation] = []
        copilot_analysis = CopilotAnalysis()

        print(f"[ScannerService] Starting scan for {request.file_path} (language: {request.language})")
        print(f"[ScannerService] Options: enable_ai={request.options.enable_ai}, rule_packs={request.options.rule_packs}")

        # 1. Run rule engine (pattern-based detection) - always runs
        try:
            rule_results = self.rule_engine.run_rules(
                code=request.code,
                file_path=request.file_path,
                language=request.language,
                enabled_packs=request.options.rule_packs if request.options.rule_packs else ["default-security"],
            )
            violations.extend(self._convert_rule_results(rule_results, request.file_path))
            print(f"[ScannerService] Rule engine found {len(rule_results)} violations")
        except Exception as e:
            print(f"[ScannerService] Rule engine failed: {e}")

        # 2. AI-powered analysis (optional) - run in parallel for speed
        if request.options.enable_ai:
            print(f"[ScannerService] Starting AI analysis in parallel...")

            async def safe_security_analysis():
                try:
                    return await self.ai_client.analyze_security(
                        code=request.code,
                        file_path=request.file_path,
                        language=request.language,
                    )
                except Exception as e:
                    print(f"AI security analysis failed: {e}")
                    return {"violations": []}

            async def safe_standards_analysis():
                try:
                    return await self.ai_client.analyze_standards(
                        code=request.code,
                        file_path=request.file_path,
                        language=request.language,
                    )
                except Exception as e:
                    print(f"AI standards analysis failed: {e}")
                    return {"violations": []}

            async def safe_copilot_detection():
                try:
                    return await self.ai_client.detect_copilot_code(
                        code=request.code,
                        file_path=request.file_path,
                        language=request.language,
                    )
                except Exception as e:
                    print(f"AI copilot detection failed: {e}")
                    return {"is_ai_generated": False, "confidence": 0, "ai_code_lines": []}

            # Run all AI analyses in parallel
            security_result, standards_result, copilot_result = await asyncio.gather(
                safe_security_analysis(),
                safe_standards_analysis(),
                safe_copilot_detection(),
            )

            print(f"[ScannerService] AI analysis completed")

            # Process results
            violations.extend(self._convert_ai_violations(
                security_result.get("violations", []),
                Category.SECURITY,
                request.file_path,
            ))
            violations.extend(self._convert_ai_violations(
                standards_result.get("violations", []),
                Category.STANDARDS,
                request.file_path,
            ))
            copilot_analysis = CopilotAnalysis(
                detected_ai_code=copilot_result.get("is_ai_generated", False),
                ai_code_percentage=copilot_result.get("confidence", 0) / 100,
                ai_code_lines=copilot_result.get("ai_code_lines", []),
            )

        # Deduplicate violations (rule engine and AI may find same issues)
        violations = self._deduplicate_violations(violations)
        print(f"[ScannerService] After deduplication: {len(violations)} unique violations")

        # Calculate summary
        summary = self._calculate_summary(violations)

        # Determine enforcement action
        enforcement_action = self._determine_enforcement(
            summary,
            request.options.enforcement_mode.value,
        )

        # Determine status
        status = "clean" if summary.total_issues == 0 else "violations_found"

        # Save to database (non-blocking - don't fail scan if save fails)
        try:
            await self._save_scan_result(
                scan_id=scan_id,
                request=request,
                status=status,
                summary=summary,
                violations=violations,
                copilot_analysis=copilot_analysis,
                enforcement_action=enforcement_action,
            )
        except Exception as e:
            print(f"Failed to save scan result to database (scan will still return results): {e}")

        return ScanResponse(
            scan_id=scan_id,
            status=status,
            summary=summary,
            violations=violations,
            copilot_analysis=copilot_analysis,
            enforcement_action=enforcement_action,
            created_at=datetime.utcnow(),
        )

    async def scan_security(self, request: ScanRequest) -> SecurityScanResponse:
        """Perform security-focused scan only."""
        scan_id = str(uuid.uuid4())
        violations: list[Violation] = []

        # Run rule engine security rules first
        rule_results = self.rule_engine.run_security_rules(
            code=request.code,
            file_path=request.file_path,
            language=request.language,
        )
        violations.extend(self._convert_rule_results(rule_results, request.file_path))

        # Then optionally run AI analysis
        if request.options.enable_ai:
            security_result = await self.ai_client.analyze_security(
                code=request.code,
                file_path=request.file_path,
                language=request.language,
            )
            violations = self._convert_ai_violations(
                security_result.get("violations", []),
                Category.SECURITY,
                request.file_path,
            )

        summary = self._calculate_summary(violations)
        status = "clean" if summary.total_issues == 0 else "violations_found"

        # Build OWASP coverage map
        owasp_coverage = {}
        for v in violations:
            if v.owasp_mapping:
                owasp_coverage[v.owasp_mapping] = owasp_coverage.get(v.owasp_mapping, 0) + 1

        return SecurityScanResponse(
            scan_id=scan_id,
            status=status,
            summary=summary,
            violations=violations,
            owasp_coverage=owasp_coverage,
        )

    async def scan_standards(self, request: ScanRequest) -> StandardsScanResponse:
        """Perform enterprise standards scan only."""
        scan_id = str(uuid.uuid4())
        violations: list[Violation] = []

        # Run rule engine standards rules first
        rule_results = self.rule_engine.run_standards_rules(
            code=request.code,
            file_path=request.file_path,
            language=request.language,
        )
        violations.extend(self._convert_rule_results(rule_results, request.file_path))

        # Then optionally run AI analysis
        if request.options.enable_ai:
            standards_result = await self.ai_client.analyze_standards(
                code=request.code,
                file_path=request.file_path,
                language=request.language,
            )
            violations = self._convert_ai_violations(
                standards_result.get("violations", []),
                Category.STANDARDS,
                request.file_path,
            )

        summary = self._calculate_summary(violations)
        status = "clean" if summary.total_issues == 0 else "violations_found"

        # Build standards compliance map
        standards_compliance = {
            "naming": True,
            "logging": True,
            "error_handling": True,
        }
        for v in violations:
            details = v.description.lower()
            if "naming" in details:
                standards_compliance["naming"] = False
            if "logging" in details or "console" in details:
                standards_compliance["logging"] = False
            if "error" in details or "catch" in details:
                standards_compliance["error_handling"] = False

        return StandardsScanResponse(
            scan_id=scan_id,
            status=status,
            summary=summary,
            violations=violations,
            standards_compliance=standards_compliance,
        )

    async def log_audit(self, result: ScanResponse) -> None:
        """Log scan result to audit log."""
        audit_log = AuditLogModel(
            event_type="scan",
            org=result.violations[0].file_path.split("/")[0] if result.violations else "unknown",
            repo="unknown",  # Will be set from context
            action_taken=result.enforcement_action,
            scan_id=result.scan_id,
            violations_count=result.summary.total_issues,
            details={
                "summary": result.summary.model_dump(),
                "copilot_detected": result.copilot_analysis.detected_ai_code,
            },
        )
        self.db.add(audit_log)
        await self.db.commit()

    def _convert_rule_results(
        self,
        rule_results: list[RuleResult],
        file_path: str,
    ) -> list[Violation]:
        """Convert rule engine results to Violation schema."""
        violations = []
        for r in rule_results:
            # Map RuleSeverity to Severity
            severity_map = {
                RuleSeverity.CRITICAL: Severity.CRITICAL,
                RuleSeverity.HIGH: Severity.HIGH,
                RuleSeverity.MEDIUM: Severity.MEDIUM,
                RuleSeverity.LOW: Severity.LOW,
                RuleSeverity.INFO: Severity.INFO,
            }
            # Map RuleCategory to Category
            category_map = {
                RuleCategory.SECURITY: Category.SECURITY,
                RuleCategory.STANDARDS: Category.STANDARDS,
                RuleCategory.LICENSE: Category.LICENSE,
            }

            violations.append(Violation(
                id=str(uuid.uuid4()),
                rule_id=r.rule_id,
                severity=severity_map.get(r.severity, Severity.MEDIUM),
                category=category_map.get(r.category, Category.SECURITY),
                title=r.title,
                description=r.description,
                file_path=file_path,
                line_start=r.line_start,
                line_end=r.line_end,
                code_snippet=r.code_snippet,
                owasp_mapping=r.owasp_mapping,
                cwe_id=r.cwe_id,
                is_ai_generated=False,
                explanation=r.description,
                suggested_fix=r.suggested_fix,
                fix_diff=None,
                references=r.references,
            ))
        return violations

    def _convert_ai_violations(
        self,
        ai_violations: list[dict],
        category: Category,
        file_path: str,
    ) -> list[Violation]:
        """Convert AI response violations to Violation schema."""
        violations = []
        for v in ai_violations:
            severity_str = v.get("severity", "medium").lower()
            try:
                severity = Severity(severity_str)
            except ValueError:
                severity = Severity.MEDIUM

            violations.append(Violation(
                id=str(uuid.uuid4()),
                rule_id=f"AI-{category.value.upper()}-{len(violations) + 1:03d}",
                severity=severity,
                category=category,
                title=v.get("title", "Unknown Issue"),
                description=v.get("description", "No description provided"),
                file_path=file_path,
                line_start=v.get("line_start", 1),
                line_end=v.get("line_end", v.get("line_start", 1)),
                code_snippet=v.get("code_snippet", ""),
                owasp_mapping=v.get("owasp_mapping"),
                cwe_id=v.get("cwe_id"),
                is_ai_generated=False,
                explanation=v.get("explanation", v.get("description", "")),
                suggested_fix=v.get("suggested_fix"),
                fix_diff=v.get("fix_diff"),
                references=v.get("references", []),
            ))
        return violations

    def _deduplicate_violations(self, violations: list[Violation]) -> list[Violation]:
        """Remove duplicate violations at the same location."""
        seen: set[tuple[str, int, int]] = set()
        unique_violations: list[Violation] = []

        for v in violations:
            # Key based on file path and line location
            key = (v.file_path, v.line_start, v.line_end)
            if key not in seen:
                seen.add(key)
                unique_violations.append(v)

        return unique_violations

    def _calculate_summary(self, violations: list[Violation]) -> ScanSummary:
        """Calculate summary from violations."""
        summary = ScanSummary()
        summary.total_issues = len(violations)
        for v in violations:
            if v.severity == Severity.CRITICAL:
                summary.critical += 1
            elif v.severity == Severity.HIGH:
                summary.high += 1
            elif v.severity == Severity.MEDIUM:
                summary.medium += 1
            elif v.severity == Severity.LOW:
                summary.low += 1
            else:
                summary.info += 1
        return summary

    def _determine_enforcement(
        self,
        summary: ScanSummary,
        mode: str,
    ) -> str:
        """Determine enforcement action based on summary and mode."""
        if mode == "advisory":
            return "none"
        elif mode == "warning":
            if summary.total_issues > 0:
                return "annotate"
            return "none"
        elif mode == "blocking":
            if summary.critical > 0 or summary.high > 0:
                return "block"
            elif summary.total_issues > 0:
                return "annotate"
            return "none"
        return "none"

    async def _save_scan_result(
        self,
        scan_id: str,
        request: ScanRequest,
        status: str,
        summary: ScanSummary,
        violations: list[Violation],
        copilot_analysis: CopilotAnalysis,
        enforcement_action: str,
    ) -> None:
        """Save scan result to database."""
        scan_result = ScanResultModel(
            id=scan_id,
            org=request.context.org,
            repo=request.context.repo,
            pr_number=request.context.pr_number,
            commit_sha=request.context.commit_sha,
            file_path=request.file_path,
            language=request.language,
            scan_type="full",
            status=status,
            summary=summary.model_dump(),
            violations=[v.model_dump() for v in violations],
            copilot_analysis=copilot_analysis.model_dump(),
            enforcement_action=enforcement_action,
        )
        self.db.add(scan_result)

        # Save individual violations for querying
        for v in violations:
            violation_model = ViolationModel(
                id=v.id,
                scan_id=scan_id,
                rule_id=v.rule_id,
                severity=v.severity.value,
                category=v.category.value,
                title=v.title,
                file_path=v.file_path,
                line_start=v.line_start,
                line_end=v.line_end,
                owasp_mapping=v.owasp_mapping,
                cwe_id=v.cwe_id,
                is_ai_generated=v.is_ai_generated,
            )
            self.db.add(violation_model)

        await self.db.commit()
