import pytest
from app.rules.security.secrets import HardcodedSecretsRule
from app.rules.base import Severity, Category


class TestHardcodedSecretsRule:
    """Tests for the HardcodedSecretsRule."""

    @pytest.fixture
    def rule(self):
        return HardcodedSecretsRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "SEC-001"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY
        assert rule.owasp_mapping is not None
        assert rule.cwe_id == "CWE-798"

    def test_detects_api_key(self, rule):
        """Test detection of hardcoded API keys."""
        code = '''
const API_KEY = "sk_live_abc123xyz789def456ghi";
'''
        results = rule.check(code, "src/config.ts", "typescript")
        assert len(results) >= 1
        assert any("API" in r.title or "Secret" in r.title for r in results)

    def test_detects_password(self, rule):
        """Test detection of hardcoded passwords."""
        code = '''
password = "supersecretpassword123"
'''
        results = rule.check(code, "src/auth.py", "python")
        assert len(results) >= 1
        assert any("Password" in r.title for r in results)

    def test_detects_aws_keys(self, rule):
        """Test detection of AWS credentials."""
        code = '''
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
'''
        results = rule.check(code, "config.py", "python")
        assert len(results) >= 1

    def test_detects_github_token(self, rule):
        """Test detection of GitHub tokens."""
        code = '''
const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
'''
        results = rule.check(code, "auth.js", "javascript")
        assert len(results) >= 1
        assert any("GitHub" in r.title for r in results)

    def test_detects_private_key(self, rule):
        """Test detection of private keys."""
        code = '''
const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;
'''
        results = rule.check(code, "certs.js", "javascript")
        assert len(results) >= 1
        assert any("Private Key" in r.title for r in results)

    def test_ignores_env_variables(self, rule):
        """Test that environment variable references are ignored."""
        code = '''
const apiKey = process.env.API_KEY;
api_key = os.environ.get("API_KEY")
'''
        results = rule.check(code, "config.ts", "typescript")
        # Should not detect environment variable references
        assert len(results) == 0

    def test_ignores_placeholders(self, rule):
        """Test that placeholder values are ignored."""
        code = '''
API_KEY = "your-api-key-here"
SECRET = "<change-me>"
TOKEN = "xxx-placeholder-xxx"
'''
        results = rule.check(code, "config.py", "python")
        assert len(results) == 0

    def test_ignores_test_files(self, rule):
        """Test that test files are excluded."""
        code = '''
API_KEY = "sk_test_realkey123456789"
'''
        results = rule.check(code, "src/auth.test.ts", "typescript")
        assert len(results) == 0

        results = rule.check(code, "tests/test_auth.py", "python")
        assert len(results) == 0

    def test_detects_database_connection_string(self, rule):
        """Test detection of database connection strings with credentials."""
        code = '''
DATABASE_URL = "postgresql://admin:secretpass@localhost:5432/mydb"
'''
        results = rule.check(code, "config.py", "python")
        assert len(results) >= 1

    def test_clean_code_no_violations(self, rule, sample_clean_code):
        """Test that clean code produces no violations."""
        results = rule.check(sample_clean_code, "clean.py", "python")
        assert len(results) == 0

    def test_result_has_correct_structure(self, rule):
        """Test that results have correct structure."""
        code = 'const secret = "mysupersecrettoken12345678";'
        results = rule.check(code, "file.ts", "typescript")

        if results:
            result = results[0]
            assert result.rule_id == "SEC-001"
            assert result.severity == Severity.CRITICAL
            assert result.category == Category.SECURITY
            assert result.file_path == "file.ts"
            assert result.line_start > 0
            assert result.explanation != ""
