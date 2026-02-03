import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class HardcodedSecretsRule(BaseRule):
    """Detect hardcoded secrets, API keys, passwords, and tokens."""

    rule_id = "SEC-001"
    name = "Hardcoded Secrets Detection"
    description = "Detects hardcoded secrets, API keys, passwords, and tokens in source code"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = []  # All languages
    owasp_mapping = "A07:2021 - Identification and Authentication Failures"
    cwe_id = "CWE-798"
    references = [
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ]

    # Patterns for detecting secrets
    SECRET_PATTERNS = [
        # API Keys
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key"),
        (r'(?i)(api[_-]?secret|apisecret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Secret"),

        # AWS
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?(AKIA[0-9A-Z]{16})["\']?', "AWS Access Key ID"),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', "AWS Secret Access Key"),

        # Generic passwords
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Password"),

        # Generic secrets
        (r'(?i)(secret|token|auth[_-]?token)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})["\']', "Secret/Token"),

        # Private keys
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
        (r'-----BEGIN OPENSSH PRIVATE KEY-----', "SSH Private Key"),

        # GitHub tokens
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
        (r'ghu_[a-zA-Z0-9]{36}', "GitHub User Token"),
        (r'ghs_[a-zA-Z0-9]{36}', "GitHub Server Token"),

        # Slack
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', "Slack Token"),

        # Stripe
        (r'sk_live_[a-zA-Z0-9]{24,}', "Stripe Secret Key"),
        (r'rk_live_[a-zA-Z0-9]{24,}', "Stripe Restricted Key"),

        # Database connection strings
        (r'(?i)(mongodb|postgres|mysql|redis)://[^"\'\s]+:[^"\'\s]+@', "Database Connection String"),

        # JWT
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token"),

        # Generic high entropy strings that look like secrets
        (r'(?i)(secret|key|token|password|credential)["\']?\s*[=:]\s*["\']([a-zA-Z0-9+/=_\-]{32,})["\']', "Generic Secret"),
    ]

    # Files/patterns to exclude (test files, examples, etc.)
    EXCLUDE_PATTERNS = [
        r'\.test\.',
        r'\.spec\.',
        r'_test\.',
        r'test_',
        r'\.example',
        r'\.sample',
        r'mock',
        r'fixture',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []

        # Skip excluded files
        for exclude in self.EXCLUDE_PATTERNS:
            if re.search(exclude, file_path, re.IGNORECASE):
                return results

        lines = code.split('\n')

        for pattern, secret_type in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, code):
                # Find line number
                line_start = code[:match.start()].count('\n') + 1
                line_end = line_start

                # Get the line content
                if line_start <= len(lines):
                    code_snippet = lines[line_start - 1].strip()
                else:
                    code_snippet = match.group(0)

                # Skip if it looks like a placeholder
                matched_text = match.group(0)
                if self._is_placeholder(matched_text):
                    continue

                # Skip environment variable references
                if self._is_env_reference(matched_text):
                    continue

                results.append(self._create_result(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code_snippet,
                    title=f"Hardcoded {secret_type} Detected",
                    description=f"A hardcoded {secret_type.lower()} was found in the source code. "
                               "This is a security risk as secrets in code can be exposed through "
                               "version control, logs, or code sharing.",
                    explanation=f"Hardcoded secrets pose a significant security risk. If this code "
                               f"is committed to version control, the {secret_type.lower()} could be "
                               "exposed to anyone with access to the repository. Attackers often "
                               "scan public repositories for leaked credentials.",
                    suggested_fix=self._get_fix_suggestion(secret_type, language),
                ))

        return results

    def _is_placeholder(self, text: str) -> bool:
        """Check if the matched text is likely a placeholder."""
        placeholders = [
            'xxx', 'your-', 'change-me', 'placeholder', 'example',
            'sample', 'test', 'dummy', 'fake', '<', '>', '${', '{{'
        ]
        text_lower = text.lower()
        return any(p in text_lower for p in placeholders)

    def _is_env_reference(self, text: str) -> bool:
        """Check if this is an environment variable reference."""
        env_patterns = [
            r'process\.env\.',
            r'os\.environ',
            r'os\.getenv',
            r'\$\{?\w+\}?',
            r'ENV\[',
            r'getenv\(',
        ]
        return any(re.search(p, text) for p in env_patterns)

    def _get_fix_suggestion(self, secret_type: str, language: str) -> str:
        """Get language-specific fix suggestion."""
        if language in ['typescript', 'javascript']:
            return f'''// Use environment variables instead of hardcoding secrets
const {secret_type.lower().replace(' ', '_')} = process.env.{secret_type.upper().replace(' ', '_')};
if (!{secret_type.lower().replace(' ', '_')}) {{
  throw new Error('{secret_type.upper().replace(' ', '_')} environment variable is required');
}}'''
        elif language == 'python':
            return f'''import os

# Use environment variables instead of hardcoding secrets
{secret_type.lower().replace(' ', '_')} = os.environ.get('{secret_type.upper().replace(' ', '_')}')
if not {secret_type.lower().replace(' ', '_')}:
    raise ValueError('{secret_type.upper().replace(' ', '_')} environment variable is required')'''
        else:
            return f"Store the {secret_type.lower()} in environment variables or a secure secrets manager."
