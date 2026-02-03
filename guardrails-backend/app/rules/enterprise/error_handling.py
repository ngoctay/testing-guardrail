import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class ErrorHandlingRule(BaseRule):
    """Check for error handling violations."""

    rule_id = "STD-003"
    name = "Error Handling Violations"
    description = "Detects empty catch blocks and swallowed exceptions"
    severity = Severity.HIGH
    category = Category.STANDARDS
    languages = ["javascript", "typescript", "python", "java"]
    owasp_mapping = None
    cwe_id = "CWE-390"
    references = [
        "https://cwe.mitre.org/data/definitions/390.html",
        "https://docs.python.org/3/tutorial/errors.html",
    ]

    # Patterns for detecting error handling issues
    EMPTY_CATCH_PATTERNS = {
        'javascript': [
            # Empty catch block
            (r'catch\s*\([^)]*\)\s*\{\s*\}', 'empty catch block'),
            # Catch with only comment
            (r'catch\s*\([^)]*\)\s*\{\s*//[^\n]*\s*\}', 'catch with only comment'),
            # Catch that doesn't use the error
            (r'catch\s*\(\s*_\s*\)\s*\{', 'catch ignoring error with _'),
        ],
        'typescript': [
            (r'catch\s*\([^)]*\)\s*\{\s*\}', 'empty catch block'),
            (r'catch\s*\([^)]*\)\s*\{\s*//[^\n]*\s*\}', 'catch with only comment'),
            (r'catch\s*\(\s*_\s*\)\s*\{', 'catch ignoring error with _'),
        ],
        'python': [
            # Bare except
            (r'except\s*:\s*\n\s*pass', 'bare except with pass'),
            # Exception with pass
            (r'except\s+\w+\s*:\s*\n\s*pass', 'except with pass'),
            # Except with only comment
            (r'except[^:]*:\s*\n\s*#[^\n]*\n\s*pass', 'except with only comment'),
            # Bare except (catches all)
            (r'except\s*:', 'bare except (catches all exceptions)'),
        ],
        'java': [
            # Empty catch block
            (r'catch\s*\([^)]*\)\s*\{\s*\}', 'empty catch block'),
            # Catch with only comment
            (r'catch\s*\([^)]*\)\s*\{\s*//[^\n]*\s*\}', 'catch with only comment'),
        ],
    }

    # Patterns that indicate proper error handling
    PROPER_HANDLING_PATTERNS = [
        r'log',
        r'throw',
        r'raise',
        r'console\.error',
        r'logger\.',
        r'logging\.',
        r'return',
        r'reject',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()

        patterns = self.EMPTY_CATCH_PATTERNS.get(lang_lower, [])
        lines = code.split('\n')

        for pattern, issue_type in patterns:
            for match in re.finditer(pattern, code, re.MULTILINE | re.IGNORECASE):
                line_start = code[:match.start()].count('\n') + 1
                line_end = code[:match.end()].count('\n') + 1

                # Get code snippet
                snippet_lines = lines[line_start - 1:min(line_end + 2, len(lines))]
                code_snippet = '\n'.join(snippet_lines).strip()

                # Check if there's actually some handling we missed
                if self._has_proper_handling(code_snippet):
                    continue

                results.append(self._create_result(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code_snippet,
                    title=f"Improper error handling: {issue_type}",
                    description=f"Detected {issue_type}. Errors should be properly "
                               "logged or handled, not silently ignored.",
                    explanation="Empty catch blocks or swallowed exceptions hide errors "
                               "and make debugging extremely difficult. Errors should "
                               "always be logged, re-thrown, or handled meaningfully. "
                               "Silent failures can lead to data corruption, security "
                               "issues, and hard-to-diagnose bugs.",
                    suggested_fix=self._get_fix_suggestion(lang_lower),
                ))

        # Check for async functions without try-catch in JS/TS
        if lang_lower in ['javascript', 'typescript']:
            results.extend(self._check_unhandled_async(code, file_path, lines))

        return results

    def _has_proper_handling(self, code_snippet: str) -> bool:
        """Check if the catch block has proper error handling."""
        for pattern in self.PROPER_HANDLING_PATTERNS:
            if re.search(pattern, code_snippet, re.IGNORECASE):
                return True
        return False

    def _check_unhandled_async(
        self,
        code: str,
        file_path: str,
        lines: list[str]
    ) -> list[RuleResult]:
        """Check for async functions that might have unhandled rejections."""
        results = []

        # Find async functions
        async_pattern = r'async\s+(?:function\s+)?(\w+)?\s*\([^)]*\)\s*\{'

        for match in re.finditer(async_pattern, code):
            func_start = match.start()
            func_name = match.group(1) or 'anonymous'

            # Find the function body
            brace_count = 1
            pos = match.end()
            while pos < len(code) and brace_count > 0:
                if code[pos] == '{':
                    brace_count += 1
                elif code[pos] == '}':
                    brace_count -= 1
                pos += 1

            func_body = code[match.end():pos]

            # Check if there's a try-catch in the function
            has_try_catch = 'try' in func_body and 'catch' in func_body

            # Check if there's a .catch() call
            has_catch_call = '.catch' in func_body

            # Check if errors are handled
            if not has_try_catch and not has_catch_call and 'await' in func_body:
                line_start = code[:func_start].count('\n') + 1
                code_snippet = lines[line_start - 1].strip() if line_start <= len(lines) else ""

                # Only flag if it's not already being called with .catch() elsewhere
                # This is a heuristic and might have false positives
                if len(func_body) > 50:  # Skip very short functions
                    results.append(self._create_result(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=code_snippet,
                        title=f"Async function '{func_name}' may have unhandled rejections",
                        description="Async function contains await calls but no try-catch. "
                                   "Unhandled promise rejections can crash the application.",
                        explanation="In async functions, any await call can throw an error. "
                                   "Without try-catch, these errors become unhandled promise "
                                   "rejections which can crash Node.js applications or cause "
                                   "silent failures in browsers.",
                        suggested_fix=self._get_async_fix_suggestion(),
                    ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        """Get language-specific fix suggestion."""
        if language in ['javascript', 'typescript']:
            return '''// Always handle errors properly
try {
  // risky operation
} catch (error) {
  // Log the error
  logger.error('Operation failed', { error, context: 'operation_name' });

  // Re-throw if it should bubble up
  throw error;

  // Or handle gracefully
  // return defaultValue;
}'''

        elif language == 'python':
            return '''# Always handle errors properly
try:
    # risky operation
except SpecificException as e:
    # Log the error
    logger.error('Operation failed', exc_info=True, extra={'context': 'operation_name'})

    # Re-raise if it should bubble up
    raise

    # Or handle gracefully
    # return default_value'''

        elif language == 'java':
            return '''// Always handle errors properly
try {
    // risky operation
} catch (SpecificException e) {
    // Log the error
    logger.error("Operation failed", e);

    // Re-throw if it should bubble up
    throw e;

    // Or handle gracefully
    // return defaultValue;
}'''

        return "Always log or re-throw exceptions. Never use empty catch blocks."

    def _get_async_fix_suggestion(self) -> str:
        """Get fix suggestion for async functions."""
        return '''// Wrap async operations in try-catch
async function myFunction() {
  try {
    const result = await riskyOperation();
    return result;
  } catch (error) {
    logger.error('Operation failed', { error });
    throw error; // or handle gracefully
  }
}

// Or use .catch() when calling
myFunction().catch(error => {
  logger.error('Unhandled error', { error });
});'''
