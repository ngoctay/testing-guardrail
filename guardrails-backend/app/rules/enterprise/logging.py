import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class LoggingRequirementsRule(BaseRule):
    """Check for logging requirement violations."""

    rule_id = "STD-002"
    name = "Logging Requirements"
    description = "Detects console.log usage and missing structured logging"
    severity = Severity.MEDIUM
    category = Category.STANDARDS
    languages = ["javascript", "typescript", "python"]
    owasp_mapping = None
    cwe_id = None
    references = [
        "https://12factor.net/logs",
        "https://www.loggly.com/ultimate-guide/node-logging-basics/",
    ]

    # Patterns for console logging (should be avoided in production)
    CONSOLE_PATTERNS = {
        'javascript': [
            (r'console\.log\s*\(', 'console.log'),
            (r'console\.info\s*\(', 'console.info'),
            (r'console\.warn\s*\(', 'console.warn'),
            (r'console\.error\s*\(', 'console.error'),
            (r'console\.debug\s*\(', 'console.debug'),
        ],
        'typescript': [
            (r'console\.log\s*\(', 'console.log'),
            (r'console\.info\s*\(', 'console.info'),
            (r'console\.warn\s*\(', 'console.warn'),
            (r'console\.error\s*\(', 'console.error'),
            (r'console\.debug\s*\(', 'console.debug'),
        ],
        'python': [
            (r'print\s*\(', 'print()'),
        ],
    }

    # Files to exclude (tests, dev tools, etc.)
    EXCLUDE_PATTERNS = [
        r'\.test\.',
        r'\.spec\.',
        r'_test\.',
        r'test_',
        r'/tests?/',
        r'__tests__',
        r'\.config\.',
        r'webpack\.',
        r'vite\.',
        r'jest\.',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()

        # Skip excluded files
        for exclude in self.EXCLUDE_PATTERNS:
            if re.search(exclude, file_path, re.IGNORECASE):
                return results

        patterns = self.CONSOLE_PATTERNS.get(lang_lower, [])
        lines = code.split('\n')

        for pattern, log_type in patterns:
            for match in re.finditer(pattern, code, re.MULTILINE):
                line_start = code[:match.start()].count('\n') + 1
                code_snippet = lines[line_start - 1].strip() if line_start <= len(lines) else ""

                # Skip if it's commented out
                if self._is_commented(code, match.start(), lang_lower):
                    continue

                results.append(self._create_result(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_start,
                    code_snippet=code_snippet,
                    title=f"Avoid {log_type} in production code",
                    description=f"Using {log_type} is not recommended in production code. "
                               "Use a structured logging library instead.",
                    explanation=f"Console methods like {log_type} don't provide log levels, "
                               "timestamps, or structured output. They can also cause "
                               "performance issues and make it difficult to filter or "
                               "aggregate logs in production environments.",
                    suggested_fix=self._get_fix_suggestion(lang_lower, log_type),
                ))

        return results

    def _is_commented(self, code: str, position: int, language: str) -> bool:
        """Check if the position is within a comment."""
        line_start = code.rfind('\n', 0, position) + 1
        line = code[line_start:position]

        if language in ['javascript', 'typescript', 'java', 'go', 'csharp']:
            return '//' in line
        elif language == 'python':
            return '#' in line
        return False

    def _get_fix_suggestion(self, language: str, log_type: str) -> str:
        """Get language-specific logging suggestion."""
        if language in ['javascript', 'typescript']:
            return '''// Use a structured logging library like pino or winston
import pino from 'pino';

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
});

// Instead of console.log('message')
logger.info({ event: 'user_action' }, 'User performed action');
logger.error({ err, userId }, 'Error processing request');'''

        elif language == 'python':
            return '''# Use the logging module instead of print()
import logging

logger = logging.getLogger(__name__)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Instead of print('message')
logger.info('User performed action', extra={'user_id': user_id})
logger.error('Error processing request', exc_info=True)'''

        return f"Replace {log_type} with a structured logging library."
