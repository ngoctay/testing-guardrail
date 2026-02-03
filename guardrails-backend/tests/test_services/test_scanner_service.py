import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.services.scanner_service import ScannerService
from app.schemas.scan import (
    ScanRequest,
    ScanContext,
    ScanOptions,
    EnforcementMode,
    ScanSummary,
    Violation,
    Severity,
    Category,
)


class TestScannerService:
    """Tests for the ScannerService."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        return db

    @pytest.fixture
    def scanner(self, mock_db):
        """Create a scanner service instance."""
        return ScannerService(mock_db)

    @pytest.fixture
    def sample_request(self):
        """Create a sample scan request."""
        return ScanRequest(
            code='const API_KEY = "sk_live_test123456789";',
            file_path="src/config.ts",
            language="typescript",
            diff_only=False,
            context=ScanContext(
                org="test-org",
                repo="test-repo",
                pr_number=123,
                commit_sha="abc123",
            ),
            options=ScanOptions(
                enable_ai=False,
                enforcement_mode=EnforcementMode.WARNING,
                rule_packs=["default-security"],
                custom_rules=[],
            ),
        )

    def test_calculate_summary(self, scanner):
        """Test summary calculation from violations."""
        violations = [
            Violation(
                id="1",
                rule_id="SEC-001",
                severity=Severity.CRITICAL,
                category=Category.SECURITY,
                title="Critical issue",
                description="A critical issue",
                file_path="test.py",
                line_start=1,
                line_end=1,
                code_snippet="code",
                explanation="explanation",
            ),
            Violation(
                id="2",
                rule_id="SEC-002",
                severity=Severity.HIGH,
                category=Category.SECURITY,
                title="High issue",
                description="A high issue",
                file_path="test.py",
                line_start=2,
                line_end=2,
                code_snippet="code",
                explanation="explanation",
            ),
            Violation(
                id="3",
                rule_id="STD-001",
                severity=Severity.MEDIUM,
                category=Category.STANDARDS,
                title="Medium issue",
                description="A medium issue",
                file_path="test.py",
                line_start=3,
                line_end=3,
                code_snippet="code",
                explanation="explanation",
            ),
            Violation(
                id="4",
                rule_id="STD-002",
                severity=Severity.LOW,
                category=Category.STANDARDS,
                title="Low issue",
                description="A low issue",
                file_path="test.py",
                line_start=4,
                line_end=4,
                code_snippet="code",
                explanation="explanation",
            ),
        ]

        summary = scanner._calculate_summary(violations)

        assert summary.total_issues == 4
        assert summary.critical == 1
        assert summary.high == 1
        assert summary.medium == 1
        assert summary.low == 1

    def test_determine_enforcement_advisory(self, scanner):
        """Test enforcement action in advisory mode."""
        summary = ScanSummary(total_issues=5, critical=1)
        action = scanner._determine_enforcement(summary, "advisory")
        assert action == "none"

    def test_determine_enforcement_warning(self, scanner):
        """Test enforcement action in warning mode."""
        summary = ScanSummary(total_issues=5, critical=1)
        action = scanner._determine_enforcement(summary, "warning")
        assert action == "annotate"

        summary_clean = ScanSummary(total_issues=0)
        action_clean = scanner._determine_enforcement(summary_clean, "warning")
        assert action_clean == "none"

    def test_determine_enforcement_blocking_critical(self, scanner):
        """Test enforcement action in blocking mode with critical issues."""
        summary = ScanSummary(total_issues=5, critical=1)
        action = scanner._determine_enforcement(summary, "blocking")
        assert action == "block"

    def test_determine_enforcement_blocking_high(self, scanner):
        """Test enforcement action in blocking mode with high issues."""
        summary = ScanSummary(total_issues=5, high=1)
        action = scanner._determine_enforcement(summary, "blocking")
        assert action == "block"

    def test_determine_enforcement_blocking_medium_only(self, scanner):
        """Test enforcement action in blocking mode with medium issues only."""
        summary = ScanSummary(total_issues=5, medium=5)
        action = scanner._determine_enforcement(summary, "blocking")
        assert action == "annotate"

    def test_determine_enforcement_blocking_clean(self, scanner):
        """Test enforcement action in blocking mode with no issues."""
        summary = ScanSummary(total_issues=0)
        action = scanner._determine_enforcement(summary, "blocking")
        assert action == "none"

    def test_convert_ai_violations(self, scanner):
        """Test conversion of AI response to violations."""
        ai_violations = [
            {
                "title": "Hardcoded Secret",
                "description": "API key found in code",
                "severity": "critical",
                "line_start": 1,
                "line_end": 1,
                "code_snippet": "API_KEY = 'secret'",
                "owasp_mapping": "A07:2021",
                "cwe_id": "CWE-798",
                "suggested_fix": "Use environment variables",
            },
        ]

        violations = scanner._convert_ai_violations(
            ai_violations, Category.SECURITY, "test.py"
        )

        assert len(violations) == 1
        assert violations[0].title == "Hardcoded Secret"
        assert violations[0].severity == Severity.CRITICAL
        assert violations[0].category == Category.SECURITY
        assert violations[0].owasp_mapping == "A07:2021"
        assert violations[0].cwe_id == "CWE-798"

    def test_convert_ai_violations_invalid_severity(self, scanner):
        """Test conversion of AI response with invalid severity."""
        ai_violations = [
            {
                "title": "Issue",
                "description": "Description",
                "severity": "invalid_severity",
                "line_start": 1,
            },
        ]

        violations = scanner._convert_ai_violations(
            ai_violations, Category.SECURITY, "test.py"
        )

        assert len(violations) == 1
        assert violations[0].severity == Severity.MEDIUM  # Default

    @pytest.mark.asyncio
    async def test_scan_without_ai(self, scanner, sample_request, mock_db):
        """Test scan without AI enabled."""
        sample_request.options.enable_ai = False

        result = await scanner.scan(sample_request)

        assert result.scan_id is not None
        assert result.status == "clean"
        assert result.summary.total_issues == 0
        assert result.enforcement_action == "none"

    @pytest.mark.asyncio
    async def test_scan_security_without_ai(self, scanner, sample_request, mock_db):
        """Test security scan without AI enabled."""
        sample_request.options.enable_ai = False

        result = await scanner.scan_security(sample_request)

        assert result.scan_id is not None
        assert result.status == "clean"
        assert "owasp_coverage" in result.model_dump()

    @pytest.mark.asyncio
    async def test_scan_standards_without_ai(self, scanner, sample_request, mock_db):
        """Test standards scan without AI enabled."""
        sample_request.options.enable_ai = False

        result = await scanner.scan_standards(sample_request)

        assert result.scan_id is not None
        assert result.status == "clean"
        assert "standards_compliance" in result.model_dump()
