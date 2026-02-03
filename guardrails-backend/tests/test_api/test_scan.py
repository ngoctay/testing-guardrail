import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock


class TestScanEndpoints:
    """Tests for scan API endpoints."""

    def test_scan_clean_code(self, client: TestClient, sample_clean_code):
        """Test scanning clean code."""
        response = client.post(
            "/api/v1/scan",
            json={
                "code": sample_clean_code,
                "file_path": "clean.py",
                "language": "python",
                "diff_only": False,
                "context": {
                    "org": "test-org",
                    "repo": "test-repo",
                },
                "options": {
                    "enable_ai": False,  # Disable AI for unit tests
                    "enforcement_mode": "warning",
                    "rule_packs": ["default-security"],
                    "custom_rules": [],
                },
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "scan_id" in data
        assert "status" in data
        assert "summary" in data
        assert "violations" in data

    def test_scan_code_with_vulnerabilities(self, client: TestClient, sample_python_code):
        """Test scanning code with known vulnerabilities."""
        response = client.post(
            "/api/v1/scan",
            json={
                "code": sample_python_code,
                "file_path": "vulnerable.py",
                "language": "python",
                "diff_only": False,
                "context": {
                    "org": "test-org",
                    "repo": "test-repo",
                },
                "options": {
                    "enable_ai": False,
                    "enforcement_mode": "warning",
                    "rule_packs": ["default-security"],
                    "custom_rules": [],
                },
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "violations_found"
        assert data["summary"]["total_issues"] > 0

    def test_scan_security_endpoint(self, client: TestClient, sample_python_code):
        """Test the security-only scan endpoint."""
        response = client.post(
            "/api/v1/scan/security",
            json={
                "code": sample_python_code,
                "file_path": "test.py",
                "language": "python",
                "diff_only": False,
                "context": {
                    "org": "test-org",
                    "repo": "test-repo",
                },
                "options": {
                    "enable_ai": False,
                    "enforcement_mode": "warning",
                    "rule_packs": ["default-security"],
                    "custom_rules": [],
                },
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "owasp_coverage" in data

    def test_scan_standards_endpoint(self, client: TestClient, sample_typescript_code):
        """Test the standards-only scan endpoint."""
        response = client.post(
            "/api/v1/scan/standards",
            json={
                "code": sample_typescript_code,
                "file_path": "test.ts",
                "language": "typescript",
                "diff_only": False,
                "context": {
                    "org": "test-org",
                    "repo": "test-repo",
                },
                "options": {
                    "enable_ai": False,
                    "enforcement_mode": "warning",
                    "rule_packs": ["enterprise-standards"],
                    "custom_rules": [],
                },
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "standards_compliance" in data

    def test_scan_invalid_request(self, client: TestClient):
        """Test scanning with invalid request."""
        response = client.post(
            "/api/v1/scan",
            json={
                "code": "",  # Empty code
                # Missing required fields
            },
        )
        assert response.status_code == 422  # Validation error

    def test_scan_enforcement_mode_blocking(self, client: TestClient, sample_python_code):
        """Test blocking enforcement mode."""
        response = client.post(
            "/api/v1/scan",
            json={
                "code": sample_python_code,
                "file_path": "vulnerable.py",
                "language": "python",
                "diff_only": False,
                "context": {
                    "org": "test-org",
                    "repo": "test-repo",
                },
                "options": {
                    "enable_ai": False,
                    "enforcement_mode": "blocking",
                    "rule_packs": ["default-security"],
                    "custom_rules": [],
                },
            },
        )
        assert response.status_code == 200

        data = response.json()
        # Should have block action for critical issues
        if data["summary"]["critical"] > 0 or data["summary"]["high"] > 0:
            assert data["enforcement_action"] == "block"
