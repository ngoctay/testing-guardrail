import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class PathTraversalRule(BaseRule):
    """Detect potential path traversal vulnerabilities."""

    rule_id = "SEC-004"
    name = "Path Traversal Detection"
    description = "Detects potential path traversal vulnerabilities from unsafe file path handling"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "php", "ruby", "go"]
    owasp_mapping = "A01:2021 - Broken Access Control"
    cwe_id = "CWE-22"
    references = [
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
    ]

    # Patterns for detecting path traversal vulnerabilities
    DANGEROUS_PATTERNS = {
        'python': [
            (r'open\s*\([^)]*\+', 'open() with concatenation'),
            (r'open\s*\(f["\']', 'open() with f-string'),
            (r'open\s*\([^)]*\.format\s*\(', 'open() with .format()'),
            (r'os\.path\.join\s*\([^)]*request\.\w+', 'os.path.join with request data'),
            (r'Path\s*\([^)]*\+', 'Path() with concatenation'),
            (r'shutil\.copy\s*\([^)]*\+', 'shutil.copy with concatenation'),
            (r'send_file\s*\([^)]*\+', 'send_file with concatenation'),
        ],
        'javascript': [
            (r'fs\.readFile(?:Sync)?\s*\([^)]*\+', 'fs.readFile with concatenation'),
            (r'fs\.readFile(?:Sync)?\s*\(`', 'fs.readFile with template literal'),
            (r'fs\.writeFile(?:Sync)?\s*\([^)]*\+', 'fs.writeFile with concatenation'),
            (r'path\.join\s*\([^)]*req\.\w+', 'path.join with request data'),
            (r'res\.sendFile\s*\([^)]*\+', 'res.sendFile with concatenation'),
            (r'require\s*\([^)]*\+', 'require with concatenation'),
        ],
        'typescript': [
            (r'fs\.readFile(?:Sync)?\s*\([^)]*\+', 'fs.readFile with concatenation'),
            (r'fs\.readFile(?:Sync)?\s*\(`', 'fs.readFile with template literal'),
            (r'path\.join\s*\([^)]*req\.\w+', 'path.join with request data'),
            (r'res\.sendFile\s*\([^)]*\+', 'res.sendFile with concatenation'),
        ],
        'java': [
            (r'new\s+File\s*\([^)]*\+', 'new File() with concatenation'),
            (r'new\s+FileInputStream\s*\([^)]*\+', 'FileInputStream with concatenation'),
            (r'Files\.read\w+\s*\([^)]*\+', 'Files.read* with concatenation'),
            (r'Paths\.get\s*\([^)]*\+', 'Paths.get with concatenation'),
        ],
        'php': [
            (r'file_get_contents\s*\([^)]*\$', 'file_get_contents with variable'),
            (r'fopen\s*\([^)]*\$', 'fopen with variable'),
            (r'include\s*\([^)]*\$', 'include with variable'),
            (r'require\s*\([^)]*\$', 'require with variable'),
            (r'readfile\s*\([^)]*\$', 'readfile with variable'),
        ],
        'ruby': [
            (r'File\.read\s*\([^)]*#\{', 'File.read with interpolation'),
            (r'File\.open\s*\([^)]*#\{', 'File.open with interpolation'),
            (r'send_file\s*\([^)]*#\{', 'send_file with interpolation'),
            (r'IO\.read\s*\([^)]*#\{', 'IO.read with interpolation'),
        ],
        'go': [
            (r'os\.Open\s*\([^)]*\+', 'os.Open with concatenation'),
            (r'ioutil\.ReadFile\s*\([^)]*\+', 'ioutil.ReadFile with concatenation'),
            (r'filepath\.Join\s*\([^)]*r\.\w+', 'filepath.Join with request data'),
            (r'http\.ServeFile\s*\([^)]*\+', 'http.ServeFile with concatenation'),
        ],
    }

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()

        patterns = self.DANGEROUS_PATTERNS.get(lang_lower, [])
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
                    title="Potential Path Traversal Vulnerability",
                    description=f"Unsafe use of {pattern_type}. User input may be used to "
                               "construct file paths, allowing attackers to access files "
                               "outside the intended directory.",
                    explanation="Path traversal attacks (also known as directory traversal) "
                               "occur when user input is used to construct file paths without "
                               "proper validation. Attackers can use sequences like '../' to "
                               "escape the intended directory and access sensitive files like "
                               "/etc/passwd, configuration files, or source code.",
                    suggested_fix=self._get_fix_suggestion(lang_lower),
                ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        """Get language-specific fix suggestion."""
        fixes = {
            'python': '''# Validate and sanitize file paths
import os
from pathlib import Path

BASE_DIR = Path('/safe/base/directory')

def safe_read_file(user_filename):
    # Remove any path components
    safe_name = os.path.basename(user_filename)

    # Resolve the full path and verify it's within BASE_DIR
    full_path = (BASE_DIR / safe_name).resolve()

    if not str(full_path).startswith(str(BASE_DIR.resolve())):
        raise ValueError('Invalid file path')

    return full_path.read_text()''',

            'javascript': '''// Validate and sanitize file paths
const path = require('path');
const fs = require('fs');

const BASE_DIR = '/safe/base/directory';

function safeReadFile(userFilename) {
  // Remove any path components
  const safeName = path.basename(userFilename);

  // Resolve the full path
  const fullPath = path.resolve(BASE_DIR, safeName);

  // Verify it's within BASE_DIR
  if (!fullPath.startsWith(path.resolve(BASE_DIR))) {
    throw new Error('Invalid file path');
  }

  return fs.readFileSync(fullPath, 'utf-8');
}''',

            'typescript': '''// Validate and sanitize file paths
import * as path from 'path';
import * as fs from 'fs';

const BASE_DIR = '/safe/base/directory';

function safeReadFile(userFilename: string): string {
  const safeName = path.basename(userFilename);
  const fullPath = path.resolve(BASE_DIR, safeName);

  if (!fullPath.startsWith(path.resolve(BASE_DIR))) {
    throw new Error('Invalid file path');
  }

  return fs.readFileSync(fullPath, 'utf-8');
}''',

            'java': '''// Validate and sanitize file paths
import java.nio.file.Path;
import java.nio.file.Paths;

public class SafeFileAccess {
    private static final Path BASE_DIR = Paths.get("/safe/base/directory");

    public static Path safePath(String userFilename) throws SecurityException {
        // Get just the filename
        String safeName = Paths.get(userFilename).getFileName().toString();

        // Resolve and normalize
        Path fullPath = BASE_DIR.resolve(safeName).normalize();

        // Verify it's within BASE_DIR
        if (!fullPath.startsWith(BASE_DIR)) {
            throw new SecurityException("Invalid file path");
        }

        return fullPath;
    }
}''',

            'php': '''// Validate and sanitize file paths
$baseDir = '/safe/base/directory';

function safeReadFile($userFilename) {
    global $baseDir;

    // Get just the filename
    $safeName = basename($userFilename);

    // Build full path and resolve
    $fullPath = realpath($baseDir . '/' . $safeName);

    // Verify it's within base directory
    if ($fullPath === false || strpos($fullPath, realpath($baseDir)) !== 0) {
        throw new Exception('Invalid file path');
    }

    return file_get_contents($fullPath);
}''',

            'ruby': '''# Validate and sanitize file paths
BASE_DIR = '/safe/base/directory'

def safe_read_file(user_filename)
  # Get just the filename
  safe_name = File.basename(user_filename)

  # Build full path and resolve
  full_path = File.expand_path(safe_name, BASE_DIR)

  # Verify it's within BASE_DIR
  unless full_path.start_with?(File.expand_path(BASE_DIR))
    raise SecurityError, 'Invalid file path'
  end

  File.read(full_path)
end''',

            'go': '''// Validate and sanitize file paths
import (
    "path/filepath"
    "strings"
)

const baseDir = "/safe/base/directory"

func safeReadFile(userFilename string) ([]byte, error) {
    // Get just the filename
    safeName := filepath.Base(userFilename)

    // Build and clean the path
    fullPath := filepath.Clean(filepath.Join(baseDir, safeName))

    // Verify it's within baseDir
    if !strings.HasPrefix(fullPath, filepath.Clean(baseDir)) {
        return nil, errors.New("invalid file path")
    }

    return os.ReadFile(fullPath)
}''',
        }
        return fixes.get(language, "Validate and sanitize user-provided file paths. Use basename() to extract the filename and verify the resolved path is within the allowed directory.")
