import pytest
from app.rules.security.sql_injection import SQLInjectionRule
from app.rules.base import Severity, Category


class TestSQLInjectionRule:
    """Tests for the SQLInjectionRule."""

    @pytest.fixture
    def rule(self):
        return SQLInjectionRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "SEC-002"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY
        assert "A03:2021" in rule.owasp_mapping
        assert rule.cwe_id == "CWE-89"

    def test_detects_python_fstring_sql(self, rule):
        """Test detection of f-string SQL injection in Python."""
        code = '''
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)
'''
        results = rule.check(code, "db.py", "python")
        assert len(results) >= 1
        assert any("SQL" in r.title for r in results)

    def test_detects_python_format_sql(self, rule):
        """Test detection of .format() SQL injection in Python."""
        code = '''
query = "SELECT * FROM users WHERE name = '{}'".format(user_name)
'''
        results = rule.check(code, "db.py", "python")
        assert len(results) >= 1

    def test_detects_python_percent_sql(self, rule):
        """Test detection of % formatting SQL injection in Python."""
        code = '''
query = "SELECT * FROM users WHERE id = %s" % user_id
'''
        results = rule.check(code, "db.py", "python")
        assert len(results) >= 1

    def test_detects_js_template_literal_sql(self, rule):
        """Test detection of template literal SQL injection in JavaScript."""
        code = '''
const query = `SELECT * FROM users WHERE id = ${userId}`;
'''
        results = rule.check(code, "db.js", "javascript")
        assert len(results) >= 1

    def test_detects_js_concatenation_sql(self, rule):
        """Test detection of string concatenation SQL injection in JavaScript."""
        code = '''
const query = "SELECT * FROM users WHERE id = " + userId;
'''
        results = rule.check(code, "db.js", "javascript")
        assert len(results) >= 1

    def test_detects_ts_template_literal_sql(self, rule):
        """Test detection of SQL injection in TypeScript."""
        code = '''
const query = `SELECT * FROM orders WHERE customer_id = ${customerId}`;
'''
        results = rule.check(code, "db.ts", "typescript")
        assert len(results) >= 1

    def test_detects_java_concatenation_sql(self, rule):
        """Test detection of SQL injection in Java."""
        code = '''
String query = "SELECT * FROM users WHERE id = " + userId;
'''
        results = rule.check(code, "UserDao.java", "java")
        assert len(results) >= 1

    def test_safe_parameterized_query_python(self, rule):
        """Test that parameterized queries are not flagged in Python."""
        code = '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    return cursor.execute(query, (user_id,))
'''
        results = rule.check(code, "db.py", "python")
        assert len(results) == 0

    def test_safe_parameterized_query_js(self, rule):
        """Test that parameterized queries are not flagged in JavaScript."""
        code = '''
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
'''
        results = rule.check(code, "db.js", "javascript")
        assert len(results) == 0

    def test_detects_where_clause_injection(self, rule):
        """Test detection of WHERE clause injection."""
        code = '''
query = "SELECT * FROM products WHERE category = '" + userInput + "'"
'''
        results = rule.check(code, "products.js", "javascript")
        assert len(results) >= 1

    def test_supports_multiple_languages(self, rule):
        """Test that rule supports multiple languages."""
        assert "python" in rule.languages
        assert "javascript" in rule.languages
        assert "typescript" in rule.languages
        assert "java" in rule.languages

    def test_result_has_fix_suggestion(self, rule):
        """Test that results include fix suggestions."""
        code = '''
query = f"SELECT * FROM users WHERE id = {user_id}"
'''
        results = rule.check(code, "db.py", "python")

        if results:
            assert results[0].suggested_fix is not None
            assert len(results[0].suggested_fix) > 0
