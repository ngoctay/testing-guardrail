import pytest
from app.rules.engine import RuleEngine
from app.rules.base import BaseRule, RuleResult, Severity, Category


class TestRuleEngine:
    """Tests for the RuleEngine."""

    @pytest.fixture
    def engine(self):
        return RuleEngine()

    def test_builtin_rules_registered(self, engine):
        """Test that built-in rules are registered."""
        rules = engine.list_rules()
        assert len(rules) >= 7  # At least 7 built-in rules

        rule_ids = [r.rule_id for r in rules]
        assert "SEC-001" in rule_ids  # Secrets
        assert "SEC-002" in rule_ids  # SQL Injection
        assert "SEC-003" in rule_ids  # Command Injection
        assert "SEC-004" in rule_ids  # Path Traversal
        assert "STD-001" in rule_ids  # Naming
        assert "STD-002" in rule_ids  # Logging
        assert "STD-003" in rule_ids  # Error Handling

    def test_builtin_packs_registered(self, engine):
        """Test that built-in rule packs are registered."""
        packs = engine.list_packs()
        assert "default-security" in packs
        assert "enterprise-standards" in packs

    def test_get_rule(self, engine):
        """Test getting a specific rule."""
        rule = engine.get_rule("SEC-001")
        assert rule is not None
        assert rule.rule_id == "SEC-001"

    def test_get_nonexistent_rule(self, engine):
        """Test getting a non-existent rule."""
        rule = engine.get_rule("NONEXISTENT-001")
        assert rule is None

    def test_register_custom_rule(self, engine):
        """Test registering a custom rule."""
        class CustomRule(BaseRule):
            rule_id = "CUSTOM-001"
            name = "Custom Rule"
            description = "A custom test rule"
            severity = Severity.LOW
            category = Category.STANDARDS
            languages = ["python"]

            def check(self, code, file_path, language):
                return []

        engine.register_rule(CustomRule())
        assert engine.get_rule("CUSTOM-001") is not None

    def test_unregister_rule(self, engine):
        """Test unregistering a rule."""
        engine.unregister_rule("SEC-001")
        assert engine.get_rule("SEC-001") is None

    def test_run_rules_all(self, engine):
        """Test running all rules."""
        code = '''
API_KEY = "sk_live_realkey123456789"
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        results = engine.run_rules(code, "test.py", "python")
        assert len(results) >= 2  # At least secrets and SQL injection

    def test_run_rules_with_pack(self, engine):
        """Test running rules from a specific pack."""
        code = '''
API_KEY = "sk_live_realkey123456789"
'''
        results = engine.run_rules(
            code, "test.py", "python",
            enabled_packs=["default-security"]
        )
        # Should find the secret
        assert any(r.rule_id == "SEC-001" for r in results)

    def test_run_rules_with_specific_rules(self, engine):
        """Test running specific rules only."""
        code = '''
API_KEY = "sk_live_realkey123456789"
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        results = engine.run_rules(
            code, "test.py", "python",
            enabled_rules=["SEC-001"]  # Only secrets
        )
        # Should only find secrets, not SQL injection
        assert all(r.rule_id == "SEC-001" for r in results)

    def test_run_security_rules(self, engine):
        """Test running only security rules."""
        code = '''
API_KEY = "sk_live_realkey123456789"
console.log("debug");
'''
        results = engine.run_security_rules(code, "test.js", "javascript")
        # Should find security issues only
        assert all(r.category == Category.SECURITY for r in results)

    def test_run_standards_rules(self, engine):
        """Test running only standards rules."""
        code = '''
console.log("debug message");

try {
    riskyOperation();
} catch (e) {
    // ignore
}
'''
        results = engine.run_standards_rules(code, "test.js", "javascript")
        # Should find standards issues only
        assert all(r.category == Category.STANDARDS for r in results)

    def test_language_filtering(self, engine):
        """Test that rules are filtered by language support."""
        code = '''
API_KEY = "sk_live_realkey123456789"
'''
        # Python is supported
        results = engine.run_rules(code, "test.py", "python")
        assert len(results) >= 1

    def test_get_pack_rules(self, engine):
        """Test getting rules from a pack."""
        rules = engine.get_pack_rules("default-security")
        assert len(rules) >= 4  # At least 4 security rules
        assert all(r.category == Category.SECURITY for r in rules)

    def test_register_pack(self, engine):
        """Test registering a custom pack."""
        engine.register_pack("custom-pack", ["SEC-001", "SEC-002"])
        packs = engine.list_packs()
        assert "custom-pack" in packs
        assert packs["custom-pack"] == ["SEC-001", "SEC-002"]

    def test_clean_code_no_violations(self, engine, sample_clean_code):
        """Test that clean code produces no security violations."""
        results = engine.run_security_rules(sample_clean_code, "clean.py", "python")
        # Clean code should have no critical/high security issues
        critical_high = [r for r in results if r.severity in [Severity.CRITICAL, Severity.HIGH]]
        assert len(critical_high) == 0
