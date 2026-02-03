import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class NamingConventionRule(BaseRule):
    """Check for naming convention violations."""

    rule_id = "STD-001"
    name = "Naming Convention Violations"
    description = "Detects violations of standard naming conventions"
    severity = Severity.MEDIUM
    category = Category.STANDARDS
    languages = ["python", "javascript", "typescript", "java"]
    owasp_mapping = None
    cwe_id = None
    references = [
        "https://peps.python.org/pep-0008/#naming-conventions",
        "https://google.github.io/styleguide/tsguide.html#naming-conventions",
    ]

    # Naming patterns by language and type
    CONVENTIONS = {
        'python': {
            'function': (r'def\s+([a-z][a-z0-9_]*)\s*\(', 'snake_case', r'^[a-z][a-z0-9_]*$'),
            'class': (r'class\s+([A-Z][a-zA-Z0-9]*)\s*[:\(]', 'PascalCase', r'^[A-Z][a-zA-Z0-9]*$'),
            'constant': (r'([A-Z][A-Z0-9_]*)\s*=\s*(?!.*class|def)', 'SCREAMING_SNAKE_CASE', r'^[A-Z][A-Z0-9_]*$'),
            'variable': (r'^\s*([a-z][a-z0-9_]*)\s*=', 'snake_case', r'^[a-z][a-z0-9_]*$'),
        },
        'javascript': {
            'function': (r'(?:function|const|let|var)\s+([a-zA-Z][a-zA-Z0-9]*)\s*(?:=\s*(?:async\s*)?\(?|[\(])', 'camelCase', r'^[a-z][a-zA-Z0-9]*$'),
            'class': (r'class\s+([A-Z][a-zA-Z0-9]*)', 'PascalCase', r'^[A-Z][a-zA-Z0-9]*$'),
            'constant': (r'const\s+([A-Z][A-Z0-9_]*)\s*=', 'SCREAMING_SNAKE_CASE', r'^[A-Z][A-Z0-9_]*$'),
        },
        'typescript': {
            'function': (r'(?:function|const|let)\s+([a-zA-Z][a-zA-Z0-9]*)\s*(?:<[^>]*>)?\s*(?:=\s*(?:async\s*)?\(?|[\(])', 'camelCase', r'^[a-z][a-zA-Z0-9]*$'),
            'class': (r'class\s+([A-Z][a-zA-Z0-9]*)', 'PascalCase', r'^[A-Z][a-zA-Z0-9]*$'),
            'interface': (r'interface\s+([A-Z][a-zA-Z0-9]*)', 'PascalCase', r'^[A-Z][a-zA-Z0-9]*$'),
            'type': (r'type\s+([A-Z][a-zA-Z0-9]*)\s*=', 'PascalCase', r'^[A-Z][a-zA-Z0-9]*$'),
            'constant': (r'const\s+([A-Z][A-Z0-9_]*)\s*=', 'SCREAMING_SNAKE_CASE', r'^[A-Z][A-Z0-9_]*$'),
        },
        'java': {
            'method': (r'(?:public|private|protected|static|\s)+\w+\s+([a-z][a-zA-Z0-9]*)\s*\(', 'camelCase', r'^[a-z][a-zA-Z0-9]*$'),
            'class': (r'class\s+([A-Z][a-zA-Z0-9]*)', 'PascalCase', r'^[A-Z][a-zA-Z0-9]*$'),
            'constant': (r'(?:static\s+final|final\s+static)\s+\w+\s+([A-Z][A-Z0-9_]*)\s*=', 'SCREAMING_SNAKE_CASE', r'^[A-Z][A-Z0-9_]*$'),
        },
    }

    # Names to ignore (common exceptions)
    IGNORE_NAMES = {
        'i', 'j', 'k', 'x', 'y', 'z',  # Loop variables
        'id', 'db', 'fs', 'os',  # Common abbreviations
        '_', '__',  # Underscore variables
    }

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()

        if lang_lower not in self.CONVENTIONS:
            return results

        conventions = self.CONVENTIONS[lang_lower]
        lines = code.split('\n')

        for element_type, (pattern, convention_name, valid_pattern) in conventions.items():
            for match in re.finditer(pattern, code, re.MULTILINE):
                name = match.group(1)

                # Skip ignored names
                if name in self.IGNORE_NAMES:
                    continue

                # Check if name matches the expected pattern
                if not re.match(valid_pattern, name):
                    line_start = code[:match.start()].count('\n') + 1
                    code_snippet = lines[line_start - 1].strip() if line_start <= len(lines) else ""

                    results.append(self._create_result(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=code_snippet,
                        title=f"{element_type.capitalize()} name '{name}' violates {convention_name} convention",
                        description=f"The {element_type} name '{name}' should follow {convention_name} convention.",
                        explanation=f"Consistent naming conventions improve code readability and "
                                   f"maintainability. {element_type.capitalize()}s in {language} should "
                                   f"use {convention_name} naming.",
                        suggested_fix=self._suggest_fix(name, element_type, lang_lower),
                    ))

        return results

    def _suggest_fix(self, name: str, element_type: str, language: str) -> str:
        """Suggest a corrected name."""
        if language == 'python':
            if element_type == 'class':
                # Convert to PascalCase
                fixed = ''.join(word.capitalize() for word in re.split(r'[_\s]+', name))
                return f"Rename to: {fixed}"
            else:
                # Convert to snake_case
                fixed = re.sub(r'([A-Z])', r'_\1', name).lower().lstrip('_')
                return f"Rename to: {fixed}"
        else:
            if element_type in ['class', 'interface', 'type']:
                # Convert to PascalCase
                fixed = ''.join(word.capitalize() for word in re.split(r'[_\s]+', name))
                return f"Rename to: {fixed}"
            elif element_type == 'constant':
                # Convert to SCREAMING_SNAKE_CASE
                fixed = re.sub(r'([A-Z])', r'_\1', name).upper().lstrip('_')
                return f"Rename to: {fixed}"
            else:
                # Convert to camelCase
                words = re.split(r'[_\s]+', name)
                fixed = words[0].lower() + ''.join(word.capitalize() for word in words[1:])
                return f"Rename to: {fixed}"
