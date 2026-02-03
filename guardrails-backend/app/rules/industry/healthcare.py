"""Healthcare (HIPAA) compliance rules.

HIPAA (Health Insurance Portability and Accountability Act) requires
specific safeguards for Protected Health Information (PHI).
"""

import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class PHILoggingRule(BaseRule):
    """Detect potential PHI being logged or printed."""

    rule_id = "HIPAA-001"
    name = "PHI Logging Prevention"
    description = "Detects potential Protected Health Information (PHI) being logged or printed"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "csharp", "go"]
    owasp_mapping = "A09:2021 - Security Logging and Monitoring Failures"
    cwe_id = "CWE-532"
    references = [
        "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
        "https://cwe.mitre.org/data/definitions/532.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
    ]

    # PHI-related variable names and patterns
    PHI_INDICATORS = [
        r'patient[_\s]?name',
        r'patient[_\s]?id',
        r'medical[_\s]?record',
        r'mrn',  # Medical Record Number
        r'ssn',  # Social Security Number
        r'social[_\s]?security',
        r'date[_\s]?of[_\s]?birth',
        r'dob',
        r'diagnosis',
        r'treatment',
        r'prescription',
        r'health[_\s]?record',
        r'insurance[_\s]?id',
        r'policy[_\s]?number',
        r'beneficiary',
        r'medical[_\s]?history',
        r'lab[_\s]?result',
        r'test[_\s]?result',
        r'blood[_\s]?type',
        r'allergy',
        r'medication',
        r'pharmacy',
        r'physician',
        r'doctor[_\s]?name',
        r'provider[_\s]?id',
        r'npi',  # National Provider Identifier
        r'encounter',
        r'admission',
        r'discharge',
    ]

    # Logging patterns by language
    LOGGING_PATTERNS = {
        'python': [r'print\s*\(', r'logging\.\w+\s*\(', r'logger\.\w+\s*\('],
        'javascript': [r'console\.\w+\s*\(', r'logger\.\w+\s*\('],
        'typescript': [r'console\.\w+\s*\(', r'logger\.\w+\s*\('],
        'java': [r'System\.out\.print', r'logger\.\w+\s*\(', r'log\.\w+\s*\('],
        'csharp': [r'Console\.Write', r'_logger\.\w+\s*\(', r'Log\.\w+\s*\('],
        'go': [r'fmt\.Print', r'log\.\w+\s*\('],
    }

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()
        lines = code.split('\n')

        log_patterns = self.LOGGING_PATTERNS.get(lang_lower, [])

        for log_pattern in log_patterns:
            for match in re.finditer(log_pattern, code, re.IGNORECASE):
                # Get the full line/statement
                line_start = code[:match.start()].count('\n') + 1
                line_content = lines[line_start - 1] if line_start <= len(lines) else ""

                # Check if any PHI indicator is in the same line or nearby
                for phi_pattern in self.PHI_INDICATORS:
                    if re.search(phi_pattern, line_content, re.IGNORECASE):
                        results.append(self._create_result(
                            file_path=file_path,
                            line_start=line_start,
                            line_end=line_start,
                            code_snippet=line_content.strip(),
                            title="Potential PHI being logged",
                            description=f"Detected potential PHI field '{phi_pattern}' being logged. "
                                       "Logging PHI violates HIPAA regulations.",
                            explanation="HIPAA requires that Protected Health Information (PHI) not be "
                                       "logged in plaintext. PHI includes patient names, dates of birth, "
                                       "Social Security Numbers, medical record numbers, diagnosis codes, "
                                       "and any other information that could identify a patient.",
                            suggested_fix=self._get_fix_suggestion(lang_lower),
                        ))
                        break

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        if language in ['python']:
            return '''# Avoid logging PHI directly
# Instead, log non-identifying information or use anonymization

# Bad:
# logger.info(f"Processing patient {patient_name}")

# Good:
logger.info("Processing patient record", extra={
    "patient_id_hash": hash_patient_id(patient_id),  # Use hashed IDs
    "action": "record_processing"
})

# Or use a PHI-safe logger that automatically redacts
phi_safe_logger.info("Processing patient", patient_id=patient_id)'''

        return '''// Avoid logging PHI directly
// Instead, log non-identifying information or use anonymization

// Bad:
// console.log(`Processing patient ${patientName}`);

// Good:
logger.info('Processing patient record', {
  patientIdHash: hashPatientId(patientId),  // Use hashed IDs
  action: 'record_processing'
});'''


class EncryptionRequiredRule(BaseRule):
    """Detect PHI stored or transmitted without encryption."""

    rule_id = "HIPAA-002"
    name = "PHI Encryption Required"
    description = "Detects PHI data that may be stored or transmitted without encryption"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "csharp", "go"]
    owasp_mapping = "A02:2021 - Cryptographic Failures"
    cwe_id = "CWE-311"
    references = [
        "https://www.hhs.gov/hipaa/for-professionals/security/guidance/guidance-risk-analysis-requirements/index.html",
        "https://cwe.mitre.org/data/definitions/311.html",
    ]

    # Patterns indicating unencrypted storage/transmission
    UNENCRYPTED_PATTERNS = {
        'python': [
            (r'open\s*\([^)]+["\']w["\']', 'Writing to file without encryption'),
            (r'json\.dump\s*\(', 'Storing JSON without encryption'),
            (r'pickle\.dump\s*\(', 'Storing pickle without encryption'),
            (r'sqlite3\.connect', 'SQLite database (consider encryption)'),
        ],
        'javascript': [
            (r'localStorage\.setItem', 'Storing in localStorage (unencrypted)'),
            (r'sessionStorage\.setItem', 'Storing in sessionStorage'),
            (r'fs\.writeFile', 'Writing to file without encryption'),
            (r'indexedDB\.open', 'IndexedDB storage (consider encryption)'),
        ],
        'typescript': [
            (r'localStorage\.setItem', 'Storing in localStorage (unencrypted)'),
            (r'sessionStorage\.setItem', 'Storing in sessionStorage'),
            (r'fs\.writeFile', 'Writing to file without encryption'),
        ],
        'java': [
            (r'FileOutputStream', 'File output without encryption'),
            (r'ObjectOutputStream', 'Object serialization without encryption'),
            (r'SharedPreferences', 'SharedPreferences (Android - unencrypted)'),
        ],
    }

    # PHI field patterns to look for nearby
    PHI_FIELDS = [
        r'patient', r'medical', r'health', r'diagnosis', r'treatment',
        r'ssn', r'dob', r'mrn', r'insurance', r'prescription',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()
        lines = code.split('\n')

        patterns = self.UNENCRYPTED_PATTERNS.get(lang_lower, [])

        for pattern, pattern_desc in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_start = code[:match.start()].count('\n') + 1

                # Check surrounding context (5 lines before and after)
                start_line = max(0, line_start - 5)
                end_line = min(len(lines), line_start + 5)
                context = '\n'.join(lines[start_line:end_line])

                # Check if PHI fields are nearby
                for phi_field in self.PHI_FIELDS:
                    if re.search(phi_field, context, re.IGNORECASE):
                        code_snippet = lines[line_start - 1].strip() if line_start <= len(lines) else ""

                        results.append(self._create_result(
                            file_path=file_path,
                            line_start=line_start,
                            line_end=line_start,
                            code_snippet=code_snippet,
                            title=f"PHI may be stored without encryption: {pattern_desc}",
                            description="Detected potential PHI data being stored or transmitted "
                                       "without encryption. HIPAA requires encryption for PHI at rest and in transit.",
                            explanation="HIPAA's Security Rule requires covered entities to implement "
                                       "technical safeguards to protect PHI. This includes encryption "
                                       "for data at rest (stored data) and data in transit (transmitted data). "
                                       "Unencrypted PHI can lead to data breaches and significant penalties.",
                            suggested_fix=self._get_fix_suggestion(lang_lower),
                        ))
                        break

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        if language == 'python':
            return '''# Use encryption for PHI storage
from cryptography.fernet import Fernet

# Generate or load encryption key (store securely!)
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt before storing
encrypted_data = cipher.encrypt(phi_data.encode())

# Use encrypted database for SQLite
# pip install sqlcipher3
import sqlcipher3
conn = sqlcipher3.connect('encrypted.db')
conn.execute("PRAGMA key='your-secure-key'")'''

        return '''// Use encryption for PHI storage

// For browser storage, use the Web Crypto API
async function encryptPHI(data: string, key: CryptoKey): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(data)
  );
  return encrypted;
}

// For Node.js file storage
import { createCipheriv, randomBytes } from 'crypto';

function encryptData(data: string, key: Buffer): string {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}'''


class HIPAAAuditTrailRule(BaseRule):
    """Detect missing audit trail for PHI access."""

    rule_id = "HIPAA-003"
    name = "PHI Audit Trail Required"
    description = "Detects PHI access without proper audit logging"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java"]
    owasp_mapping = "A09:2021 - Security Logging and Monitoring Failures"
    cwe_id = "CWE-778"
    references = [
        "https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html",
        "https://cwe.mitre.org/data/definitions/778.html",
    ]

    # Patterns indicating PHI access
    PHI_ACCESS_PATTERNS = [
        (r'get[_\s]?patient', 'Patient data access'),
        (r'fetch[_\s]?medical', 'Medical record fetch'),
        (r'read[_\s]?health', 'Health record read'),
        (r'query[_\s]?patient', 'Patient data query'),
        (r'load[_\s]?medical', 'Medical record load'),
        (r'retrieve[_\s]?phi', 'PHI retrieval'),
        (r'access[_\s]?record', 'Record access'),
        (r'view[_\s]?patient', 'Patient view'),
        (r'download[_\s]?medical', 'Medical download'),
        (r'export[_\s]?health', 'Health data export'),
    ]

    # Audit logging patterns
    AUDIT_PATTERNS = [
        r'audit[_\s]?log',
        r'log[_\s]?audit',
        r'audit[_\s]?trail',
        r'access[_\s]?log',
        r'phi[_\s]?audit',
        r'hipaa[_\s]?log',
        r'compliance[_\s]?log',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lines = code.split('\n')

        for pattern, access_type in self.PHI_ACCESS_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_start = code[:match.start()].count('\n') + 1

                # Check surrounding context (10 lines before and after)
                start_line = max(0, line_start - 10)
                end_line = min(len(lines), line_start + 10)
                context = '\n'.join(lines[start_line:end_line])

                # Check if audit logging is present
                has_audit = any(
                    re.search(audit_pattern, context, re.IGNORECASE)
                    for audit_pattern in self.AUDIT_PATTERNS
                )

                if not has_audit:
                    code_snippet = lines[line_start - 1].strip() if line_start <= len(lines) else ""

                    results.append(self._create_result(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=code_snippet,
                        title=f"PHI access without audit trail: {access_type}",
                        description=f"Detected {access_type} without apparent audit logging. "
                                   "HIPAA requires audit trails for all PHI access.",
                        explanation="HIPAA's Security Rule requires covered entities to implement "
                                   "audit controls to record and examine activity in systems that "
                                   "contain or use PHI. This includes logging who accessed PHI, "
                                   "when, what was accessed, and the purpose of the access.",
                        suggested_fix=self._get_fix_suggestion(language.lower()),
                    ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        if language == 'python':
            return '''# Add HIPAA-compliant audit logging for PHI access
import logging
from datetime import datetime

audit_logger = logging.getLogger('hipaa_audit')

def get_patient_record(patient_id: str, user_id: str, purpose: str):
    # Log before access
    audit_logger.info(
        'PHI_ACCESS',
        extra={
            'event_type': 'phi_read',
            'user_id': user_id,
            'patient_id_hash': hash(patient_id),  # Don't log actual ID
            'access_purpose': purpose,
            'timestamp': datetime.utcnow().isoformat(),
            'ip_address': get_client_ip(),
        }
    )

    record = database.get_patient(patient_id)

    # Log after successful access
    audit_logger.info(
        'PHI_ACCESS_COMPLETE',
        extra={
            'event_type': 'phi_read_success',
            'user_id': user_id,
            'fields_accessed': list(record.keys()),
        }
    )

    return record'''

        return '''// Add HIPAA-compliant audit logging for PHI access

interface AuditEntry {
  eventType: 'phi_read' | 'phi_write' | 'phi_delete';
  userId: string;
  patientIdHash: string;
  accessPurpose: string;
  timestamp: string;
  ipAddress: string;
}

async function getPatientRecord(
  patientId: string,
  userId: string,
  purpose: string
): Promise<PatientRecord> {
  // Log before access
  await auditLogger.log({
    eventType: 'phi_read',
    userId,
    patientIdHash: hashPatientId(patientId),
    accessPurpose: purpose,
    timestamp: new Date().toISOString(),
    ipAddress: getClientIp(),
  });

  const record = await database.getPatient(patientId);

  // Log after successful access
  await auditLogger.log({
    eventType: 'phi_read_success',
    userId,
    fieldsAccessed: Object.keys(record),
  });

  return record;
}'''
