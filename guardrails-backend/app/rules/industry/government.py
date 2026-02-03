"""Government (FedRAMP) compliance rules.

FedRAMP (Federal Risk and Authorization Management Program) provides a
standardized approach to security assessment, authorization, and continuous
monitoring for cloud products and services.
"""

import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class AccessControlRule(BaseRule):
    """Detect missing or improper access control implementations."""

    rule_id = "FED-001"
    name = "FedRAMP Access Control"
    description = "Detects missing or improper access control in government systems"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "go", "csharp"]
    owasp_mapping = "A01:2021 - Broken Access Control"
    cwe_id = "CWE-284"
    references = [
        "https://www.fedramp.gov/",
        "https://nvd.nist.gov/800-53",
        "https://cwe.mitre.org/data/definitions/284.html",
    ]

    # API endpoint patterns that typically need access control
    SENSITIVE_ENDPOINT_PATTERNS = {
        'python': [
            (r'@app\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']+["\']', 'FastAPI/Flask endpoint'),
            (r'@router\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']+["\']', 'Router endpoint'),
            (r'def\s+(?:get|post|put|delete|patch|create|update|remove)\w*\s*\(', 'CRUD operation'),
        ],
        'javascript': [
            (r'app\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']+["\']', 'Express endpoint'),
            (r'router\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']+["\']', 'Router endpoint'),
            (r'async\s+function\s+(?:get|post|put|delete|create|update|remove)\w*\s*\(', 'Async handler'),
        ],
        'typescript': [
            (r'@(?:Get|Post|Put|Delete|Patch)\s*\(["\'][^"\']*["\']?\)', 'NestJS endpoint'),
            (r'app\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']+["\']', 'Express endpoint'),
            (r'router\.(?:get|post|put|delete|patch)\s*\(["\'][^"\']+["\']', 'Router endpoint'),
        ],
        'java': [
            (r'@(?:Get|Post|Put|Delete|Patch)Mapping\s*\(', 'Spring endpoint'),
            (r'@RequestMapping\s*\(', 'Request mapping'),
            (r'public\s+\w+\s+(?:get|post|put|delete|create|update|remove)\w*\s*\(', 'Handler method'),
        ],
        'go': [
            (r'\.(?:GET|POST|PUT|DELETE|PATCH)\s*\(["\'][^"\']+["\']', 'HTTP handler'),
            (r'func\s+\w*(?:Get|Post|Put|Delete|Create|Update|Remove)\w*\s*\(', 'Handler function'),
        ],
        'csharp': [
            (r'\[Http(?:Get|Post|Put|Delete|Patch)\]', '.NET endpoint'),
            (r'public\s+\w+\s+(?:Get|Post|Put|Delete|Create|Update|Remove)\w*\s*\(', 'Controller action'),
        ],
    }

    # Patterns indicating proper access control
    ACCESS_CONTROL_PATTERNS = [
        r'@require[_\s]?auth',
        r'@authenticate',
        r'@authorize',
        r'@permission',
        r'@role',
        r'@protected',
        r'@guard',
        r'middleware.*auth',
        r'check[_\s]?permission',
        r'verify[_\s]?token',
        r'validate[_\s]?session',
        r'is[_\s]?authorized',
        r'has[_\s]?permission',
        r'rbac',
        r'acl',
        r'policy',
        r'\.authorize\s*\(',
        r'UseAuthorization',
        r'RequireAuthorization',
        r'AllowAnonymous',  # Explicit bypass is acceptable
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()
        lines = code.split('\n')

        endpoint_patterns = self.SENSITIVE_ENDPOINT_PATTERNS.get(lang_lower, [])

        for endpoint_pattern, pattern_desc in endpoint_patterns:
            for match in re.finditer(endpoint_pattern, code, re.IGNORECASE):
                line_start = code[:match.start()].count('\n') + 1

                # Check surrounding context (10 lines before)
                start_line = max(0, line_start - 10)
                context_before = '\n'.join(lines[start_line:line_start])
                line_content = lines[line_start - 1] if line_start <= len(lines) else ""

                # Also check a few lines after for middleware
                end_line = min(len(lines), line_start + 3)
                context_after = '\n'.join(lines[line_start:end_line])
                full_context = context_before + line_content + context_after

                # Check if access control is present
                has_access_control = any(
                    re.search(ac_pattern, full_context, re.IGNORECASE)
                    for ac_pattern in self.ACCESS_CONTROL_PATTERNS
                )

                if not has_access_control:
                    results.append(self._create_result(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=line_content.strip(),
                        title=f"Missing access control: {pattern_desc}",
                        description="API endpoint or sensitive operation detected without apparent "
                                   "access control. FedRAMP requires strict access control (AC controls).",
                        explanation="FedRAMP's Access Control (AC) family requires that systems "
                                   "implement access control policies and enforcement mechanisms. "
                                   "All endpoints should verify user identity and authorization "
                                   "before allowing access to resources. This includes role-based "
                                   "access control (RBAC), attribute-based access control (ABAC), "
                                   "or similar mechanisms.",
                        suggested_fix=self._get_fix_suggestion(lang_lower),
                    ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        suggestions = {
            'python': '''# Add access control to endpoints
from functools import wraps

def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: User = Depends(get_current_user), **kwargs):
            if not has_permission(current_user, permission):
                raise HTTPException(403, "Insufficient permissions")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

@app.get("/sensitive-data")
@require_permission("read:sensitive_data")
async def get_sensitive_data(current_user: User = Depends(get_current_user)):
    # Access is now controlled
    return {"data": "sensitive"}''',

            'javascript': '''// Add access control middleware
const requirePermission = (permission) => async (req, res, next) => {
  const user = req.user;
  if (!user || !hasPermission(user, permission)) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
};

// Apply to endpoints
app.get('/sensitive-data',
  authenticate,  // First verify identity
  requirePermission('read:sensitive_data'),  // Then check permission
  async (req, res) => {
    res.json({ data: 'sensitive' });
  }
);''',

            'typescript': '''// Add access control decorators (NestJS example)
import { UseGuards, SetMetadata } from '@nestjs/common';

export const RequirePermission = (permission: string) =>
  SetMetadata('permission', permission);

@Controller('sensitive')
@UseGuards(AuthGuard, PermissionGuard)
export class SensitiveController {
  @Get('data')
  @RequirePermission('read:sensitive_data')
  async getSensitiveData(@CurrentUser() user: User) {
    return { data: 'sensitive' };
  }
}''',

            'java': '''// Add access control annotations (Spring Security)
@RestController
@RequestMapping("/api")
public class SensitiveController {

    @GetMapping("/sensitive-data")
    @PreAuthorize("hasAuthority('read:sensitive_data')")
    public ResponseEntity<?> getSensitiveData(
            @AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of("data", "sensitive"));
    }
}''',

            'csharp': '''// Add authorization attributes (.NET)
[ApiController]
[Route("api/[controller]")]
[Authorize]  // Require authentication
public class SensitiveController : ControllerBase
{
    [HttpGet("data")]
    [Authorize(Policy = "ReadSensitiveData")]
    public IActionResult GetSensitiveData()
    {
        return Ok(new { data = "sensitive" });
    }
}''',
        }
        return suggestions.get(language, "Add proper access control checks to all sensitive endpoints.")


class FedRAMPAuditLoggingRule(BaseRule):
    """Detect missing security event logging."""

    rule_id = "FED-002"
    name = "FedRAMP Audit Logging"
    description = "Detects missing audit logging for security-relevant events"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "go", "csharp"]
    owasp_mapping = "A09:2021 - Security Logging and Monitoring Failures"
    cwe_id = "CWE-778"
    references = [
        "https://www.fedramp.gov/",
        "https://nvd.nist.gov/800-53/Rev4/control/AU-2",
        "https://cwe.mitre.org/data/definitions/778.html",
    ]

    # Security-relevant events that require logging
    SECURITY_EVENTS = [
        (r'login|sign[_\s]?in|authenticate', 'Authentication event'),
        (r'logout|sign[_\s]?out', 'Logout event'),
        (r'password.*(?:change|reset|update)', 'Password change'),
        (r'permission.*(?:grant|revoke|change)', 'Permission change'),
        (r'role.*(?:assign|remove|change)', 'Role change'),
        (r'delete.*(?:user|account|record)', 'Deletion event'),
        (r'admin|administrator|superuser', 'Admin action'),
        (r'access[_\s]?denied|unauthorized|forbidden', 'Access denial'),
        (r'failed.*(?:login|auth|attempt)', 'Failed attempt'),
        (r'token.*(?:create|revoke|expire)', 'Token lifecycle'),
        (r'api[_\s]?key.*(?:create|delete|rotate)', 'API key management'),
        (r'config.*(?:change|update|modify)', 'Configuration change'),
        (r'export|download.*data', 'Data export'),
    ]

    # Audit logging patterns
    AUDIT_LOG_PATTERNS = [
        r'audit[_\s]?log',
        r'security[_\s]?log',
        r'log[_\s]?event',
        r'event[_\s]?log',
        r'\.audit\s*\(',
        r'\.security\s*\(',
        r'AuditLogger',
        r'SecurityLogger',
        r'emit[_\s]?event',
        r'record[_\s]?event',
        r'track[_\s]?event',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lines = code.split('\n')

        for event_pattern, event_type in self.SECURITY_EVENTS:
            for match in re.finditer(event_pattern, code, re.IGNORECASE):
                line_start = code[:match.start()].count('\n') + 1

                # Check surrounding context (5 lines before and after)
                start_line = max(0, line_start - 5)
                end_line = min(len(lines), line_start + 5)
                context = '\n'.join(lines[start_line:end_line])
                line_content = lines[line_start - 1] if line_start <= len(lines) else ""

                # Check if audit logging is present
                has_audit_log = any(
                    re.search(audit_pattern, context, re.IGNORECASE)
                    for audit_pattern in self.AUDIT_LOG_PATTERNS
                )

                if not has_audit_log:
                    results.append(self._create_result(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=line_content.strip(),
                        title=f"Missing audit log: {event_type}",
                        description=f"Security-relevant event ({event_type}) detected without "
                                   "apparent audit logging. FedRAMP requires comprehensive audit logging.",
                        explanation="FedRAMP's Audit and Accountability (AU) controls require logging "
                                   "of security-relevant events including: successful and unsuccessful "
                                   "authentication attempts, access to sensitive data, privilege "
                                   "escalation, administrative actions, and security-relevant "
                                   "configuration changes. Logs must capture who, what, when, where, "
                                   "and outcome information.",
                        suggested_fix=self._get_fix_suggestion(language.lower()),
                    ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        if language == 'python':
            return '''# Add comprehensive audit logging
import logging
from datetime import datetime

audit_logger = logging.getLogger('security.audit')

class AuditEvent:
    LOGIN_SUCCESS = 'login_success'
    LOGIN_FAILURE = 'login_failure'
    LOGOUT = 'logout'
    ACCESS_DENIED = 'access_denied'
    PERMISSION_CHANGE = 'permission_change'
    DATA_ACCESS = 'data_access'
    ADMIN_ACTION = 'admin_action'

def log_security_event(
    event_type: str,
    user_id: str,
    details: dict,
    outcome: str = 'success'
):
    """Log security-relevant event per FedRAMP AU controls."""
    audit_logger.info(
        event_type,
        extra={
            'event_type': event_type,
            'user_id': user_id,
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': get_client_ip(),
            'outcome': outcome,
            'details': details,
        }
    )

# Usage
async def login(credentials: Credentials):
    user = await authenticate(credentials)
    if user:
        log_security_event(
            AuditEvent.LOGIN_SUCCESS,
            user.id,
            {'method': 'password'}
        )
        return create_token(user)
    else:
        log_security_event(
            AuditEvent.LOGIN_FAILURE,
            credentials.username,
            {'reason': 'invalid_credentials'},
            outcome='failure'
        )
        raise HTTPException(401)'''

        return '''// Add comprehensive audit logging
interface AuditEvent {
  eventType: string;
  userId: string;
  timestamp: string;
  sourceIp: string;
  outcome: 'success' | 'failure';
  details: Record<string, unknown>;
}

const AuditEventTypes = {
  LOGIN_SUCCESS: 'login_success',
  LOGIN_FAILURE: 'login_failure',
  LOGOUT: 'logout',
  ACCESS_DENIED: 'access_denied',
  PERMISSION_CHANGE: 'permission_change',
  DATA_ACCESS: 'data_access',
  ADMIN_ACTION: 'admin_action',
} as const;

function logSecurityEvent(
  eventType: string,
  userId: string,
  details: Record<string, unknown>,
  outcome: 'success' | 'failure' = 'success'
): void {
  auditLogger.info({
    eventType,
    userId,
    timestamp: new Date().toISOString(),
    sourceIp: getClientIp(),
    outcome,
    details,
  });
}

// Usage
async function login(credentials: Credentials): Promise<Token> {
  const user = await authenticate(credentials);
  if (user) {
    logSecurityEvent(
      AuditEventTypes.LOGIN_SUCCESS,
      user.id,
      { method: 'password' }
    );
    return createToken(user);
  } else {
    logSecurityEvent(
      AuditEventTypes.LOGIN_FAILURE,
      credentials.username,
      { reason: 'invalid_credentials' },
      'failure'
    );
    throw new UnauthorizedError();
  }
}'''


class EncryptionStandardsRule(BaseRule):
    """Detect use of weak or deprecated cryptographic algorithms."""

    rule_id = "FED-003"
    name = "FedRAMP Encryption Standards"
    description = "Detects use of weak or deprecated cryptographic algorithms"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "go", "csharp"]
    owasp_mapping = "A02:2021 - Cryptographic Failures"
    cwe_id = "CWE-327"
    references = [
        "https://www.fedramp.gov/",
        "https://nvd.nist.gov/800-53/Rev4/control/SC-13",
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://csrc.nist.gov/projects/cryptographic-module-validation-program",
    ]

    # Weak/deprecated algorithms to flag
    WEAK_ALGORITHMS = [
        (r'MD5|md5', 'MD5 (deprecated - use SHA-256 or higher)'),
        (r'SHA1|sha1|SHA-1', 'SHA-1 (deprecated - use SHA-256 or higher)'),
        (r'DES(?!3)|des(?!3)', 'DES (deprecated - use AES-256)'),
        (r'RC4|rc4|ARC4|arc4', 'RC4 (broken - use AES)'),
        (r'RC2|rc2', 'RC2 (deprecated - use AES)'),
        (r'Blowfish|blowfish', 'Blowfish (deprecated - use AES-256)'),
        (r'ECB|ecb', 'ECB mode (insecure - use GCM or CBC with HMAC)'),
        (r'PKCS1v15|pkcs1[_\s]?v15', 'PKCS1v1.5 padding (use OAEP)'),
        (r'(?<![A-Za-z])RSA[_\s]?1024(?![0-9])', 'RSA-1024 (use RSA-2048 minimum)'),
        (r'AES[_\s]?128', 'AES-128 (FedRAMP recommends AES-256 for sensitive data)'),
    ]

    # FIPS-approved algorithms (for context)
    APPROVED_ALGORITHMS = [
        r'AES[_\s]?256',
        r'SHA[_\s]?256',
        r'SHA[_\s]?384',
        r'SHA[_\s]?512',
        r'RSA[_\s]?(?:2048|3072|4096)',
        r'ECDSA',
        r'ECDH',
        r'GCM',
        r'HMAC',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lines = code.split('\n')

        for weak_pattern, algorithm_name in self.WEAK_ALGORITHMS:
            for match in re.finditer(weak_pattern, code):
                line_start = code[:match.start()].count('\n') + 1
                line_content = lines[line_start - 1] if line_start <= len(lines) else ""

                # Skip if it's in a comment
                if self._is_in_comment(line_content, language.lower()):
                    continue

                # Skip if it's in a variable name for comparison/detection
                context = code[max(0, match.start() - 50):match.end() + 50]
                if any(skip in context.lower() for skip in ['weak', 'deprecated', 'insecure', 'forbidden', 'not_allowed']):
                    continue

                results.append(self._create_result(
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_start,
                    code_snippet=line_content.strip(),
                    title=f"Weak cryptographic algorithm: {algorithm_name}",
                    description=f"Use of {algorithm_name} detected. FedRAMP requires FIPS 140-2 "
                               "validated cryptographic modules with approved algorithms.",
                    explanation="FedRAMP's System and Communications Protection (SC) controls require "
                               "use of FIPS 140-2 validated cryptographic modules. This means using "
                               "NIST-approved algorithms: AES-256 for symmetric encryption, SHA-256 "
                               "or higher for hashing, RSA-2048+ or ECDSA for signatures, and "
                               "approved modes like GCM for authenticated encryption.",
                    suggested_fix=self._get_fix_suggestion(language.lower(), algorithm_name),
                ))

        return results

    def _is_in_comment(self, line: str, language: str) -> bool:
        """Check if the line is a comment."""
        line_stripped = line.strip()
        if language in ['python']:
            return line_stripped.startswith('#')
        elif language in ['javascript', 'typescript', 'java', 'go', 'csharp']:
            return line_stripped.startswith('//') or line_stripped.startswith('/*')
        return False

    def _get_fix_suggestion(self, language: str, algorithm: str) -> str:
        base_fix = '''# FedRAMP-compliant cryptographic choices:

## Symmetric Encryption
- Use: AES-256 in GCM mode
- Avoid: DES, 3DES, RC4, AES-128 for sensitive data

## Hashing
- Use: SHA-256, SHA-384, SHA-512
- Avoid: MD5, SHA-1

## Asymmetric Encryption
- Use: RSA-2048 minimum (RSA-4096 recommended), ECDSA P-256+
- Avoid: RSA-1024, DSA

## Key Exchange
- Use: ECDH P-256+, DH-2048+
- Avoid: DH-1024

## TLS
- Use: TLS 1.2 or 1.3 only
- Avoid: TLS 1.0, 1.1, SSL'''

        if language == 'python':
            return base_fix + '''

# Python example with FIPS-approved algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
import os

# AES-256-GCM encryption
key = os.urandom(32)  # 256 bits
nonce = os.urandom(12)
aesgcm = AESGCM(key)
encrypted = aesgcm.encrypt(nonce, plaintext, associated_data)

# SHA-256 hashing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(data)
hash_value = digest.finalize()'''

        return base_fix + '''

// JavaScript/TypeScript example
import { createCipheriv, randomBytes, createHash } from 'crypto';

// AES-256-GCM encryption
const key = randomBytes(32);  // 256 bits
const iv = randomBytes(12);
const cipher = createCipheriv('aes-256-gcm', key, iv);
const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const tag = cipher.getAuthTag();

// SHA-256 hashing
const hash = createHash('sha256');
hash.update(data);
const hashValue = hash.digest('hex');'''
