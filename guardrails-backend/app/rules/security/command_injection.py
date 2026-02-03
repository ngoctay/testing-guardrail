import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class CommandInjectionRule(BaseRule):
    """Detect potential command injection vulnerabilities."""

    rule_id = "SEC-003"
    name = "Command Injection Detection"
    description = "Detects potential command injection vulnerabilities from unsafe shell command execution"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "php", "ruby", "go"]
    owasp_mapping = "A03:2021 - Injection"
    cwe_id = "CWE-78"
    references = [
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    ]

    # Dangerous functions by language
    DANGEROUS_FUNCTIONS = {
        'python': [
            (r'os\.system\s*\([^)]*\+', 'os.system with concatenation'),
            (r'os\.system\s*\(f["\']', 'os.system with f-string'),
            (r'os\.system\s*\([^)]*\.format\s*\(', 'os.system with .format()'),
            (r'os\.popen\s*\([^)]*\+', 'os.popen with concatenation'),
            (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', 'subprocess with shell=True'),
            (r'subprocess\.run\s*\([^)]*shell\s*=\s*True', 'subprocess.run with shell=True'),
            (r'subprocess\.Popen\s*\([^)]*shell\s*=\s*True', 'subprocess.Popen with shell=True'),
            (r'eval\s*\([^)]*\+', 'eval with concatenation'),
            (r'exec\s*\([^)]*\+', 'exec with concatenation'),
        ],
        'javascript': [
            (r'child_process\.exec\s*\([^)]*\+', 'exec with concatenation'),
            (r'child_process\.exec\s*\(`', 'exec with template literal'),
            (r'require\s*\(["\']child_process["\']\)\.exec\s*\(', 'child_process.exec'),
            (r'execSync\s*\([^)]*\+', 'execSync with concatenation'),
            (r'execSync\s*\(`', 'execSync with template literal'),
            (r'spawn\s*\([^)]*\{[^}]*shell\s*:\s*true', 'spawn with shell: true'),
            (r'eval\s*\([^)]*\+', 'eval with concatenation'),
        ],
        'typescript': [
            (r'child_process\.exec\s*\([^)]*\+', 'exec with concatenation'),
            (r'child_process\.exec\s*\(`', 'exec with template literal'),
            (r'execSync\s*\([^)]*\+', 'execSync with concatenation'),
            (r'spawn\s*\([^)]*\{[^}]*shell\s*:\s*true', 'spawn with shell: true'),
            (r'eval\s*\([^)]*\+', 'eval with concatenation'),
        ],
        'java': [
            (r'Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+', 'Runtime.exec with concatenation'),
            (r'ProcessBuilder\s*\([^)]*\+', 'ProcessBuilder with concatenation'),
        ],
        'php': [
            (r'exec\s*\([^)]*\$', 'exec with variable'),
            (r'shell_exec\s*\([^)]*\$', 'shell_exec with variable'),
            (r'system\s*\([^)]*\$', 'system with variable'),
            (r'passthru\s*\([^)]*\$', 'passthru with variable'),
            (r'popen\s*\([^)]*\$', 'popen with variable'),
            (r'proc_open\s*\([^)]*\$', 'proc_open with variable'),
            (r'`[^`]*\$', 'backtick execution with variable'),
        ],
        'ruby': [
            (r'system\s*\([^)]*#\{', 'system with interpolation'),
            (r'exec\s*\([^)]*#\{', 'exec with interpolation'),
            (r'`[^`]*#\{', 'backtick execution with interpolation'),
            (r'%x\{[^}]*#\{', '%x with interpolation'),
            (r'IO\.popen\s*\([^)]*#\{', 'IO.popen with interpolation'),
        ],
        'go': [
            (r'exec\.Command\s*\([^)]*\+', 'exec.Command with concatenation'),
            (r'exec\.CommandContext\s*\([^)]*\+', 'exec.CommandContext with concatenation'),
        ],
    }

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()

        patterns = self.DANGEROUS_FUNCTIONS.get(lang_lower, [])
        lines = code.split('\n')

        for pattern, pattern_type in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE):
                line_start = code[:match.start()].count('\n') + 1
                line_end = code[:match.end()].count('\n') + 1

                snippet_lines = lines[line_start - 1:line_end]
                code_snippet = '\n'.join(snippet_lines).strip()

                results.append(self._create_result(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    code_snippet=code_snippet,
                    title="Potential Command Injection Vulnerability",
                    description=f"Unsafe use of {pattern_type}. User input may be directly "
                               "included in a shell command, allowing attackers to execute "
                               "arbitrary commands on the system.",
                    explanation="Command injection allows an attacker to execute arbitrary "
                               "operating system commands on the server. This can lead to "
                               "complete system compromise, data theft, or use of the server "
                               "for further attacks. Never pass user input directly to shell commands.",
                    suggested_fix=self._get_fix_suggestion(lang_lower),
                ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        """Get language-specific fix suggestion."""
        fixes = {
            'python': '''# Use subprocess with a list of arguments (no shell)
import subprocess
import shlex

# Safe: pass arguments as a list
subprocess.run(['ls', '-la', directory], check=True)

# If you must use user input, validate and sanitize it
def safe_command(user_input):
    # Whitelist allowed values
    allowed = ['list', 'status', 'info']
    if user_input not in allowed:
        raise ValueError('Invalid command')
    return subprocess.run(['git', user_input], check=True)''',

            'javascript': '''// Use spawn/execFile with arguments array instead of exec
const { spawn, execFile } = require('child_process');

// Safe: use execFile with arguments array
execFile('ls', ['-la', directory], (error, stdout) => {
  console.log(stdout);
});

// Or spawn
const child = spawn('ls', ['-la', directory]);''',

            'typescript': '''// Use spawn/execFile with arguments array instead of exec
import { spawn, execFile } from 'child_process';

// Safe: use execFile with arguments array
execFile('ls', ['-la', directory], (error, stdout) => {
  console.log(stdout);
});''',

            'java': '''// Use ProcessBuilder with argument list
ProcessBuilder pb = new ProcessBuilder("ls", "-la", directory);
pb.redirectErrorStream(true);
Process process = pb.start();

// Never concatenate user input into command strings''',

            'php': '''// Use escapeshellarg() or escapeshellcmd() for any user input
$safe_input = escapeshellarg($user_input);
$output = shell_exec("ls -la " . $safe_input);

// Better: avoid shell execution entirely when possible
// Use built-in functions like scandir() instead of ls''',

            'ruby': '''# Use array form of system/exec
system('ls', '-la', directory)  # Safe: arguments as separate parameters

# Or use Open3
require 'open3'
stdout, stderr, status = Open3.capture3('ls', '-la', directory)''',

            'go': '''// Use exec.Command with separate arguments
cmd := exec.Command("ls", "-la", directory)
output, err := cmd.Output()

// Never use shell=true or concatenate user input''',
        }
        return fixes.get(language, "Avoid passing user input directly to shell commands. Use parameterized execution where possible.")
