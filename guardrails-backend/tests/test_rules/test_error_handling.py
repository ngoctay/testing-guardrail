import pytest
from app.rules.enterprise.error_handling import ErrorHandlingRule
from app.rules.base import Severity, Category


class TestErrorHandlingRule:
    """Tests for the ErrorHandlingRule."""

    @pytest.fixture
    def rule(self):
        return ErrorHandlingRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "STD-003"
        assert rule.severity == Severity.HIGH
        assert rule.category == Category.STANDARDS
        assert rule.cwe_id == "CWE-390"

    def test_detects_js_empty_catch(self, rule):
        """Test detection of empty catch block in JavaScript."""
        code = '''
try {
    riskyOperation();
} catch (error) {}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) >= 1
        assert any("empty catch" in r.title.lower() for r in results)

    def test_detects_js_catch_with_only_comment(self, rule):
        """Test detection of catch block with only comment in JavaScript."""
        code = '''
try {
    riskyOperation();
} catch (error) {
    // ignore
}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) >= 1

    def test_detects_js_catch_ignoring_error(self, rule):
        """Test detection of catch ignoring error with underscore."""
        code = '''
try {
    riskyOperation();
} catch (_) {
    doSomethingElse();
}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) >= 1

    def test_detects_ts_empty_catch(self, rule):
        """Test detection of empty catch block in TypeScript."""
        code = '''
try {
    await fetchData();
} catch (error: Error) {}
'''
        results = rule.check(code, "service.ts", "typescript")
        assert len(results) >= 1

    def test_detects_python_bare_except_pass(self, rule):
        """Test detection of bare except with pass in Python."""
        code = '''
try:
    risky_operation()
except:
    pass
'''
        results = rule.check(code, "service.py", "python")
        assert len(results) >= 1

    def test_detects_python_except_with_pass(self, rule):
        """Test detection of except Exception with pass in Python."""
        code = '''
try:
    risky_operation()
except Exception:
    pass
'''
        results = rule.check(code, "service.py", "python")
        assert len(results) >= 1

    def test_detects_python_bare_except(self, rule):
        """Test detection of bare except clause in Python."""
        code = '''
try:
    risky_operation()
except:
    print("Error occurred")
'''
        results = rule.check(code, "service.py", "python")
        # Should flag bare except (catches all)
        assert any("bare except" in r.title.lower() for r in results)

    def test_detects_java_empty_catch(self, rule):
        """Test detection of empty catch block in Java."""
        code = '''
try {
    riskyOperation();
} catch (Exception e) {}
'''
        results = rule.check(code, "Service.java", "java")
        assert len(results) >= 1

    def test_allows_js_catch_with_logging(self, rule):
        """Test that catch block with logging is allowed."""
        code = '''
try {
    riskyOperation();
} catch (error) {
    logger.error('Operation failed', { error });
}
'''
        results = rule.check(code, "service.js", "javascript")
        # Proper handling should not be flagged as empty
        empty_catch_results = [r for r in results if "empty catch" in r.title.lower()]
        assert len(empty_catch_results) == 0

    def test_allows_js_catch_with_throw(self, rule):
        """Test that catch block with throw is allowed."""
        code = '''
try {
    riskyOperation();
} catch (error) {
    throw new CustomError(error.message);
}
'''
        results = rule.check(code, "service.js", "javascript")
        empty_catch_results = [r for r in results if "empty catch" in r.title.lower()]
        assert len(empty_catch_results) == 0

    def test_allows_python_except_with_logging(self, rule):
        """Test that except block with logging is allowed."""
        code = '''
try:
    risky_operation()
except Exception as e:
    logger.error("Operation failed", exc_info=True)
'''
        results = rule.check(code, "service.py", "python")
        # Should not flag as improper handling
        pass_results = [r for r in results if "pass" in r.title.lower()]
        assert len(pass_results) == 0

    def test_allows_python_except_with_raise(self, rule):
        """Test that except block with raise is allowed."""
        code = '''
try:
    risky_operation()
except Exception as e:
    logger.error("Failed")
    raise
'''
        results = rule.check(code, "service.py", "python")
        pass_results = [r for r in results if "pass" in r.title.lower()]
        assert len(pass_results) == 0

    def test_result_has_fix_suggestion(self, rule):
        """Test that results include fix suggestions."""
        code = '''
try {
    riskyOperation();
} catch (error) {}
'''
        results = rule.check(code, "service.js", "javascript")

        if results:
            assert results[0].suggested_fix is not None
            assert "log" in results[0].suggested_fix.lower() or "throw" in results[0].suggested_fix.lower()

    def test_supports_multiple_languages(self, rule):
        """Test that rule supports expected languages."""
        assert "javascript" in rule.languages
        assert "typescript" in rule.languages
        assert "python" in rule.languages
        assert "java" in rule.languages

    def test_clean_code_no_violations(self, rule, sample_clean_code):
        """Test that clean code produces no empty catch violations."""
        results = rule.check(sample_clean_code, "clean.py", "python")
        empty_catch_results = [r for r in results if "empty" in r.title.lower()]
        assert len(empty_catch_results) == 0
