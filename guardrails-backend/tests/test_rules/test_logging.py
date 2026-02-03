import pytest
from app.rules.enterprise.logging import LoggingRequirementsRule
from app.rules.base import Severity, Category


class TestLoggingRequirementsRule:
    """Tests for the LoggingRequirementsRule."""

    @pytest.fixture
    def rule(self):
        return LoggingRequirementsRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "STD-002"
        assert rule.severity == Severity.MEDIUM
        assert rule.category == Category.STANDARDS
        assert rule.owasp_mapping is None  # Not a security rule

    def test_detects_js_console_log(self, rule):
        """Test detection of console.log in JavaScript."""
        code = '''
function processData(data) {
    console.log("Processing data:", data);
    return transform(data);
}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) >= 1
        assert any("console.log" in r.title for r in results)

    def test_detects_js_console_error(self, rule):
        """Test detection of console.error in JavaScript."""
        code = '''
try {
    riskyOperation();
} catch (err) {
    console.error("Error:", err);
}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) >= 1

    def test_detects_js_console_warn(self, rule):
        """Test detection of console.warn in JavaScript."""
        code = '''
if (deprecatedFeature) {
    console.warn("This feature is deprecated");
}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) >= 1

    def test_detects_ts_console_log(self, rule):
        """Test detection of console.log in TypeScript."""
        code = '''
function processData(data: DataType): Result {
    console.log("Processing:", data);
    return transform(data);
}
'''
        results = rule.check(code, "service.ts", "typescript")
        assert len(results) >= 1

    def test_detects_python_print(self, rule):
        """Test detection of print() in Python."""
        code = '''
def process_data(data):
    print("Processing data:", data)
    return transform(data)
'''
        results = rule.check(code, "service.py", "python")
        assert len(results) >= 1
        assert any("print()" in r.title for r in results)

    def test_ignores_test_files_js(self, rule):
        """Test that JavaScript test files are ignored."""
        code = '''
describe('UserService', () => {
    it('should process data', () => {
        console.log("Test output");
        expect(result).toBe(expected);
    });
});
'''
        results = rule.check(code, "user.test.js", "javascript")
        assert len(results) == 0

    def test_ignores_test_files_py(self, rule):
        """Test that Python test files are ignored."""
        code = '''
def test_process_data():
    print("Test output")
    assert result == expected
'''
        results = rule.check(code, "test_service.py", "python")
        assert len(results) == 0

    def test_ignores_spec_files(self, rule):
        """Test that spec files are ignored."""
        code = '''
describe('Component', () => {
    console.log("Debug");
});
'''
        results = rule.check(code, "component.spec.ts", "typescript")
        assert len(results) == 0

    def test_ignores_config_files(self, rule):
        """Test that config files are ignored."""
        code = '''
console.log("Starting webpack...");
module.exports = config;
'''
        results = rule.check(code, "webpack.config.js", "javascript")
        assert len(results) == 0

    def test_ignores_commented_console(self, rule):
        """Test that commented console.log is ignored."""
        code = '''
function process() {
    // console.log("Debug message");
    return result;
}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) == 0

    def test_ignores_python_commented_print(self, rule):
        """Test that commented print is ignored in Python."""
        code = '''
def process():
    # print("Debug message")
    return result
'''
        results = rule.check(code, "service.py", "python")
        assert len(results) == 0

    def test_allows_structured_logging_js(self, rule):
        """Test that structured logging is allowed in JavaScript."""
        code = '''
import pino from 'pino';
const logger = pino();

function processData(data) {
    logger.info({ data }, 'Processing data');
    return transform(data);
}
'''
        results = rule.check(code, "service.js", "javascript")
        assert len(results) == 0

    def test_allows_structured_logging_python(self, rule):
        """Test that structured logging is allowed in Python."""
        code = '''
import logging

logger = logging.getLogger(__name__)

def process_data(data):
    logger.info("Processing data", extra={"data": data})
    return transform(data)
'''
        results = rule.check(code, "service.py", "python")
        assert len(results) == 0

    def test_result_has_fix_suggestion(self, rule):
        """Test that results include fix suggestions."""
        code = '''
console.log("Processing");
'''
        results = rule.check(code, "service.js", "javascript")

        if results:
            assert results[0].suggested_fix is not None
            assert "pino" in results[0].suggested_fix or "logger" in results[0].suggested_fix

    def test_supports_multiple_languages(self, rule):
        """Test that rule supports expected languages."""
        assert "javascript" in rule.languages
        assert "typescript" in rule.languages
        assert "python" in rule.languages
