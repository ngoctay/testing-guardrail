import pytest
from app.rules.security.command_injection import CommandInjectionRule
from app.rules.base import Severity, Category


class TestCommandInjectionRule:
    """Tests for the CommandInjectionRule."""

    @pytest.fixture
    def rule(self):
        return CommandInjectionRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "SEC-003"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY
        assert "A03:2021" in rule.owasp_mapping
        assert rule.cwe_id == "CWE-78"

    def test_detects_python_os_system_fstring(self, rule):
        """Test detection of os.system with f-string in Python."""
        code = '''
import os

def run_command(user_input):
    os.system(f"ls {user_input}")
'''
        results = rule.check(code, "cmd.py", "python")
        assert len(results) >= 1
        assert any("Command" in r.title for r in results)

    def test_detects_python_os_system_concatenation(self, rule):
        """Test detection of os.system with concatenation in Python."""
        code = '''
import os
cmd = "ls " + user_input
os.system(cmd)
'''
        results = rule.check(code, "cmd.py", "python")
        assert len(results) >= 1

    def test_detects_python_subprocess_shell_true(self, rule):
        """Test detection of subprocess with shell=True in Python."""
        code = '''
import subprocess
subprocess.run(f"echo {user_input}", shell=True)
'''
        results = rule.check(code, "cmd.py", "python")
        assert len(results) >= 1

    def test_detects_python_subprocess_call_shell(self, rule):
        """Test detection of subprocess.call with shell=True."""
        code = '''
subprocess.call(cmd, shell=True)
'''
        results = rule.check(code, "cmd.py", "python")
        assert len(results) >= 1

    def test_detects_python_popen_shell(self, rule):
        """Test detection of subprocess.Popen with shell=True."""
        code = '''
proc = subprocess.Popen(command, shell=True)
'''
        results = rule.check(code, "cmd.py", "python")
        assert len(results) >= 1

    def test_detects_python_eval(self, rule):
        """Test detection of eval with concatenation."""
        code = '''
result = eval("print(" + user_input + ")")
'''
        results = rule.check(code, "cmd.py", "python")
        assert len(results) >= 1

    def test_detects_js_child_process_exec(self, rule):
        """Test detection of child_process.exec with concatenation in JavaScript."""
        code = '''
const { exec } = require('child_process');
child_process.exec("ls " + userInput, callback);
'''
        results = rule.check(code, "cmd.js", "javascript")
        assert len(results) >= 1

    def test_detects_js_exec_template_literal(self, rule):
        """Test detection of exec with template literal in JavaScript."""
        code = '''
execSync(`rm -rf ${userInput}`);
'''
        results = rule.check(code, "cmd.js", "javascript")
        assert len(results) >= 1

    def test_detects_js_spawn_shell_true(self, rule):
        """Test detection of spawn with shell: true in JavaScript."""
        code = '''
spawn('ls', [userInput], { shell: true });
'''
        results = rule.check(code, "cmd.js", "javascript")
        assert len(results) >= 1

    def test_detects_java_runtime_exec(self, rule):
        """Test detection of Runtime.exec with concatenation in Java."""
        code = '''
Runtime.getRuntime().exec("cmd /c " + userCommand);
'''
        results = rule.check(code, "Cmd.java", "java")
        assert len(results) >= 1

    def test_detects_java_process_builder(self, rule):
        """Test detection of ProcessBuilder with concatenation in Java."""
        code = '''
ProcessBuilder pb = new ProcessBuilder("sh -c " + command);
'''
        results = rule.check(code, "Cmd.java", "java")
        assert len(results) >= 1

    def test_detects_php_exec(self, rule):
        """Test detection of exec with variable in PHP."""
        code = '''
<?php
exec("ls " . $userInput);
'''
        results = rule.check(code, "cmd.php", "php")
        assert len(results) >= 1

    def test_detects_php_shell_exec(self, rule):
        """Test detection of shell_exec with variable in PHP."""
        code = '''
<?php
$output = shell_exec($command);
'''
        results = rule.check(code, "cmd.php", "php")
        assert len(results) >= 1

    def test_detects_ruby_system_interpolation(self, rule):
        """Test detection of system with interpolation in Ruby."""
        code = '''
system("ls #{user_input}")
'''
        results = rule.check(code, "cmd.rb", "ruby")
        assert len(results) >= 1

    def test_detects_ruby_backtick(self, rule):
        """Test detection of backtick execution with interpolation in Ruby."""
        code = '''
result = `ls #{directory}`
'''
        results = rule.check(code, "cmd.rb", "ruby")
        assert len(results) >= 1

    def test_detects_go_exec_command(self, rule):
        """Test detection of exec.Command with concatenation in Go."""
        code = '''
cmd := exec.Command("sh -c " + userInput)
'''
        results = rule.check(code, "cmd.go", "go")
        assert len(results) >= 1

    def test_safe_subprocess_list(self, rule):
        """Test that safe subprocess calls are not flagged."""
        code = '''
import subprocess

# Safe: arguments as list, no shell
subprocess.run(['ls', '-la', directory], check=True)
'''
        results = rule.check(code, "cmd.py", "python")
        assert len(results) == 0

    def test_safe_js_spawn_array(self, rule):
        """Test that safe spawn calls are not flagged."""
        code = '''
const { spawn } = require('child_process');
const child = spawn('ls', ['-la', directory]);
'''
        results = rule.check(code, "cmd.js", "javascript")
        assert len(results) == 0

    def test_supports_multiple_languages(self, rule):
        """Test that rule supports multiple languages."""
        assert "python" in rule.languages
        assert "javascript" in rule.languages
        assert "typescript" in rule.languages
        assert "java" in rule.languages
        assert "php" in rule.languages
        assert "ruby" in rule.languages
        assert "go" in rule.languages

    def test_result_has_fix_suggestion(self, rule):
        """Test that results include fix suggestions."""
        code = '''
os.system(f"echo {user_input}")
'''
        results = rule.check(code, "cmd.py", "python")

        if results:
            assert results[0].suggested_fix is not None
            assert len(results[0].suggested_fix) > 0
