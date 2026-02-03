import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class SQLInjectionRule(BaseRule):
    """Detect potential SQL injection vulnerabilities."""

    rule_id = "SEC-002"
    name = "SQL Injection Detection"
    description = "Detects potential SQL injection vulnerabilities from string concatenation or formatting"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "php", "ruby", "go", "csharp"]
    owasp_mapping = "A03:2021 - Injection"
    cwe_id = "CWE-89"
    references = [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    ]

    # SQL keywords that indicate a query
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE',
        'ALTER', 'TRUNCATE', 'EXEC', 'EXECUTE', 'UNION', 'WHERE'
    ]

    # Patterns indicating dangerous string concatenation/interpolation
    DANGEROUS_PATTERNS = {
        'python': [
            # f-strings with SQL
            (r'f["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*\{[^}]+\}', 'f-string SQL'),
            # .format() with SQL
            (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*["\']\.format\s*\(', '.format() SQL'),
            # % formatting with SQL
            (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*%s[^"\']*["\'].*%', '% formatting SQL'),
            # String concatenation with SQL
            (r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*["\']\s*\+\s*\w+', 'concatenation SQL'),
        ],
        'javascript': [
            # Template literals with SQL
            (r'`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^`]*\$\{[^}]+\}', 'template literal SQL'),
            # String concatenation with SQL
            (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*["\']\s*\+\s*\w+', 'concatenation SQL'),
            (r'\+\s*["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)', 'concatenation SQL'),
        ],
        'typescript': [
            # Same as JavaScript
            (r'`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^`]*\$\{[^}]+\}', 'template literal SQL'),
            (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*["\']\s*\+\s*\w+', 'concatenation SQL'),
        ],
        'java': [
            # String concatenation with SQL
            (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*["\']\s*\+\s*\w+', 'concatenation SQL'),
            # String.format with SQL
            (r'String\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)', 'String.format SQL'),
        ],
        'php': [
            # Variable interpolation in double-quoted strings
            (r'"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*\$\w+', 'variable interpolation SQL'),
            # String concatenation
            (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*["\']\s*\.\s*\$', 'concatenation SQL'),
        ],
        'ruby': [
            # String interpolation
            (r'"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*#\{[^}]+\}', 'interpolation SQL'),
        ],
        'go': [
            # fmt.Sprintf with SQL
            (r'fmt\.Sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)', 'fmt.Sprintf SQL'),
            # String concatenation
            (r'["`][^"`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"`]*["`]\s*\+\s*\w+', 'concatenation SQL'),
        ],
        'csharp': [
            # String interpolation
            (r'\$"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*\{[^}]+\}', 'interpolation SQL'),
            # String concatenation
            (r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^"\']*["\']\s*\+\s*\w+', 'concatenation SQL'),
        ],
    }

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()

        # Get patterns for this language
        patterns = self.DANGEROUS_PATTERNS.get(lang_lower, [])

        # Also check generic patterns
        generic_patterns = [
            (r'(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\s+(?:FROM|INTO|SET)\s+.*\s*\+\s*\w+', 'concatenation'),
            (r'(?i)WHERE\s+\w+\s*=\s*["\']?\s*\+\s*\w+', 'WHERE concatenation'),
        ]
        patterns.extend(generic_patterns)

        lines = code.split('\n')

        for pattern, pattern_type in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                line_start = code[:match.start()].count('\n') + 1
                line_end = code[:match.end()].count('\n') + 1

                # Get code snippet
                snippet_lines = lines[line_start - 1:line_end]
                code_snippet = '\n'.join(snippet_lines).strip()

                results.append(self._create_result(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code_snippet,
                    title="Potential SQL Injection Vulnerability",
                    description=f"SQL query built using {pattern_type}. User input may be "
                               "directly concatenated into the SQL query, allowing attackers "
                               "to manipulate the query.",
                    explanation="SQL injection occurs when untrusted data is sent to an interpreter "
                               "as part of a command or query. An attacker can use this to access, "
                               "modify, or delete data they shouldn't have access to. This is one "
                               "of the most common and dangerous web application vulnerabilities.",
                    suggested_fix=self._get_fix_suggestion(lang_lower),
                ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        """Get language-specific fix suggestion for SQL injection."""
        fixes = {
            'python': '''# Use parameterized queries instead
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Or with SQLAlchemy
from sqlalchemy import text
result = session.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})''',

            'javascript': '''// Use parameterized queries
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);

// Or with an ORM like Prisma
const user = await prisma.user.findUnique({ where: { id: userId } });''',

            'typescript': '''// Use parameterized queries
const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);

// Or with an ORM like TypeORM
const user = await userRepository.findOne({ where: { id: userId } });''',

            'java': '''// Use PreparedStatement
PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();''',

            'php': '''// Use prepared statements with PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);''',

            'ruby': '''# Use parameterized queries with ActiveRecord
User.where("id = ?", user_id)
# Or
User.find(user_id)''',

            'go': '''// Use parameterized queries
rows, err := db.Query("SELECT * FROM users WHERE id = $1", userId)''',

            'csharp': '''// Use parameterized queries
using var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", connection);
cmd.Parameters.AddWithValue("@id", userId);''',
        }
        return fixes.get(language, "Use parameterized queries or prepared statements instead of string concatenation.")
