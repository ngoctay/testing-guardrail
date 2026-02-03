"""Telecom industry compliance rules.

Rules for telecommunications industry compliance including subscriber privacy
and data retention requirements.
"""

import re
from app.rules.base import BaseRule, RuleResult, Severity, Category


class DataRetentionRule(BaseRule):
    """Detect potential data retention violations."""

    rule_id = "TEL-001"
    name = "Data Retention Compliance"
    description = "Detects potential data retention policy violations in telecom systems"
    severity = Severity.HIGH
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "go"]
    owasp_mapping = None
    cwe_id = "CWE-1066"
    references = [
        "https://www.fcc.gov/general/telecommunications-act-1996",
        "https://cwe.mitre.org/data/definitions/1066.html",
    ]

    # Patterns indicating permanent data storage without retention policy
    PERMANENT_STORAGE_PATTERNS = {
        'python': [
            (r'\.save\s*\(\s*\)', 'Database save without TTL'),
            (r'\.insert\s*\(', 'Database insert without TTL'),
            (r'\.create\s*\(', 'Record creation without retention'),
            (r'\.put\s*\(', 'Data put without expiration'),
        ],
        'javascript': [
            (r'\.save\s*\(', 'Database save without TTL'),
            (r'\.insert\w*\s*\(', 'Database insert without TTL'),
            (r'\.create\s*\(', 'Record creation without retention'),
            (r'\.set\s*\(', 'Data set without expiration'),
        ],
        'typescript': [
            (r'\.save\s*\(', 'Database save without TTL'),
            (r'\.insert\w*\s*\(', 'Database insert without TTL'),
            (r'\.create\s*\(', 'Record creation without retention'),
        ],
        'java': [
            (r'\.save\s*\(', 'Database save without TTL'),
            (r'\.persist\s*\(', 'Entity persist without retention'),
            (r'\.insert\s*\(', 'Database insert without TTL'),
        ],
        'go': [
            (r'\.Insert\s*\(', 'Database insert without TTL'),
            (r'\.Create\s*\(', 'Record creation without retention'),
            (r'\.Save\s*\(', 'Database save without TTL'),
        ],
    }

    # Telecom-specific data types requiring retention policies
    TELECOM_DATA_PATTERNS = [
        r'call[_\s]?record',
        r'cdr',  # Call Detail Record
        r'call[_\s]?log',
        r'sms[_\s]?log',
        r'message[_\s]?log',
        r'usage[_\s]?data',
        r'billing[_\s]?record',
        r'subscriber[_\s]?data',
        r'location[_\s]?data',
        r'cell[_\s]?tower',
        r'roaming[_\s]?data',
        r'network[_\s]?log',
        r'traffic[_\s]?data',
        r'session[_\s]?data',
    ]

    # Patterns indicating proper retention handling
    RETENTION_PATTERNS = [
        r'ttl',
        r'expir',
        r'retention',
        r'purge',
        r'cleanup',
        r'archive',
        r'delete[_\s]?after',
        r'max[_\s]?age',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()
        lines = code.split('\n')

        patterns = self.PERMANENT_STORAGE_PATTERNS.get(lang_lower, [])

        for storage_pattern, pattern_desc in patterns:
            for match in re.finditer(storage_pattern, code, re.IGNORECASE):
                line_start = code[:match.start()].count('\n') + 1

                # Check surrounding context
                start_line = max(0, line_start - 10)
                end_line = min(len(lines), line_start + 10)
                context = '\n'.join(lines[start_line:end_line])

                # Check if telecom data is being stored
                is_telecom_data = any(
                    re.search(telecom_pattern, context, re.IGNORECASE)
                    for telecom_pattern in self.TELECOM_DATA_PATTERNS
                )

                if not is_telecom_data:
                    continue

                # Check if retention policy is in place
                has_retention = any(
                    re.search(retention_pattern, context, re.IGNORECASE)
                    for retention_pattern in self.RETENTION_PATTERNS
                )

                if not has_retention:
                    code_snippet = lines[line_start - 1].strip() if line_start <= len(lines) else ""

                    results.append(self._create_result(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=code_snippet,
                        title=f"Telecom data stored without retention policy: {pattern_desc}",
                        description="Telecom data appears to be stored without a data retention policy. "
                                   "Regulatory requirements mandate specific retention periods for CDRs and other data.",
                        explanation="Telecommunications regulations require specific data retention periods "
                                   "for different types of data. Call Detail Records (CDRs) may need to be "
                                   "retained for specific periods for billing disputes, legal requirements, "
                                   "and regulatory compliance. However, indefinite retention may violate "
                                   "privacy regulations. Implement automated retention policies.",
                        suggested_fix=self._get_fix_suggestion(lang_lower),
                    ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        if language == 'python':
            return '''# Implement data retention policy for telecom data
from datetime import datetime, timedelta

class CallRecord(BaseModel):
    call_id: str
    timestamp: datetime
    # Set TTL based on retention policy
    ttl: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(days=365))

# When saving, ensure retention is enforced
async def save_call_record(record: CallRecord):
    record.ttl = datetime.utcnow() + timedelta(days=RETENTION_DAYS)
    await database.insert(record, ttl=record.ttl)

# Scheduled job to purge expired records
async def purge_expired_records():
    await database.delete_many({
        "ttl": {"$lt": datetime.utcnow()}
    })'''

        return '''// Implement data retention policy for telecom data

interface CallRecord {
  callId: string;
  timestamp: Date;
  ttl: Date;  // Time-to-live for retention
}

// Set retention period based on regulatory requirements
const RETENTION_DAYS = 365;

async function saveCallRecord(record: Omit<CallRecord, 'ttl'>): Promise<void> {
  const ttl = new Date();
  ttl.setDate(ttl.getDate() + RETENTION_DAYS);

  await database.insert({
    ...record,
    ttl,
  });
}

// Scheduled job to purge expired records
async function purgeExpiredRecords(): Promise<void> {
  await database.deleteMany({
    ttl: { $lt: new Date() }
  });
}'''


class SubscriberPrivacyRule(BaseRule):
    """Detect potential subscriber privacy violations."""

    rule_id = "TEL-002"
    name = "Subscriber Privacy Protection"
    description = "Detects potential violations of subscriber privacy requirements"
    severity = Severity.CRITICAL
    category = Category.SECURITY
    languages = ["python", "javascript", "typescript", "java", "go"]
    owasp_mapping = "A01:2021 - Broken Access Control"
    cwe_id = "CWE-359"
    references = [
        "https://www.fcc.gov/consumers/guides/protecting-your-privacy",
        "https://cwe.mitre.org/data/definitions/359.html",
    ]

    # Subscriber Personally Identifiable Information (PII)
    SUBSCRIBER_PII_PATTERNS = [
        r'phone[_\s]?number',
        r'mobile[_\s]?number',
        r'msisdn',  # Mobile Station International Subscriber Directory Number
        r'imsi',    # International Mobile Subscriber Identity
        r'imei',    # International Mobile Equipment Identity
        r'subscriber[_\s]?id',
        r'account[_\s]?number',
        r'billing[_\s]?address',
        r'home[_\s]?address',
        r'location[_\s]?data',
        r'gps[_\s]?coordinate',
        r'cell[_\s]?location',
        r'call[_\s]?history',
        r'contact[_\s]?list',
        r'voicemail',
    ]

    # Patterns indicating data exposure
    EXPOSURE_PATTERNS = {
        'python': [
            (r'return\s+.*subscriber', 'Returning subscriber data'),
            (r'response\s*=.*subscriber', 'Including subscriber in response'),
            (r'json\.dumps\s*\(.*subscriber', 'Serializing subscriber data'),
            (r'print\s*\(.*subscriber', 'Printing subscriber data'),
        ],
        'javascript': [
            (r'res\.json\s*\(.*subscriber', 'Returning subscriber in response'),
            (r'res\.send\s*\(.*subscriber', 'Sending subscriber data'),
            (r'JSON\.stringify\s*\(.*subscriber', 'Serializing subscriber data'),
            (r'console\.\w+\s*\(.*subscriber', 'Logging subscriber data'),
        ],
        'typescript': [
            (r'res\.json\s*\(.*subscriber', 'Returning subscriber in response'),
            (r'res\.send\s*\(.*subscriber', 'Sending subscriber data'),
            (r'return\s+.*subscriber', 'Returning subscriber data'),
        ],
        'java': [
            (r'return\s+.*subscriber', 'Returning subscriber data'),
            (r'response\.getWriter.*subscriber', 'Writing subscriber to response'),
            (r'System\.out.*subscriber', 'Printing subscriber data'),
        ],
        'go': [
            (r'json\.Marshal\s*\(.*subscriber', 'Serializing subscriber data'),
            (r'fmt\.Print.*subscriber', 'Printing subscriber data'),
            (r'return\s+.*subscriber', 'Returning subscriber data'),
        ],
    }

    # Patterns indicating proper privacy handling
    PRIVACY_PATTERNS = [
        r'mask',
        r'redact',
        r'anonymize',
        r'sanitize',
        r'encrypt',
        r'hash',
        r'token',
        r'consent',
        r'authorize',
        r'permission',
    ]

    def check(self, code: str, file_path: str, language: str) -> list[RuleResult]:
        results = []
        lang_lower = language.lower()
        lines = code.split('\n')

        exposure_patterns = self.EXPOSURE_PATTERNS.get(lang_lower, [])

        for exposure_pattern, pattern_desc in exposure_patterns:
            for match in re.finditer(exposure_pattern, code, re.IGNORECASE):
                line_start = code[:match.start()].count('\n') + 1
                line_content = lines[line_start - 1] if line_start <= len(lines) else ""

                # Check if subscriber PII is being exposed
                has_pii = any(
                    re.search(pii_pattern, line_content, re.IGNORECASE)
                    for pii_pattern in self.SUBSCRIBER_PII_PATTERNS
                )

                if not has_pii:
                    # Also check nearby context
                    start_line = max(0, line_start - 5)
                    end_line = min(len(lines), line_start + 5)
                    context = '\n'.join(lines[start_line:end_line])
                    has_pii = any(
                        re.search(pii_pattern, context, re.IGNORECASE)
                        for pii_pattern in self.SUBSCRIBER_PII_PATTERNS
                    )

                if not has_pii:
                    continue

                # Check if privacy measures are in place
                context = '\n'.join(lines[max(0, line_start - 5):min(len(lines), line_start + 5)])
                has_privacy = any(
                    re.search(privacy_pattern, context, re.IGNORECASE)
                    for privacy_pattern in self.PRIVACY_PATTERNS
                )

                if not has_privacy:
                    results.append(self._create_result(
                        file_path=file_path,
                        line_start=line_start,
                        line_end=line_start,
                        code_snippet=line_content.strip(),
                        title=f"Subscriber PII exposure: {pattern_desc}",
                        description="Subscriber personally identifiable information may be exposed "
                                   "without proper privacy protections.",
                        explanation="Telecommunications regulations require strict protection of "
                                   "subscriber information including phone numbers, location data, "
                                   "call records, and account information. Data should be masked, "
                                   "anonymized, or encrypted before exposure. Access should be "
                                   "authorized and consent-based where required.",
                        suggested_fix=self._get_fix_suggestion(lang_lower),
                    ))

        return results

    def _get_fix_suggestion(self, language: str) -> str:
        if language == 'python':
            return '''# Protect subscriber PII before exposure
def mask_phone_number(phone: str) -> str:
    """Mask phone number for display."""
    if len(phone) >= 4:
        return '*' * (len(phone) - 4) + phone[-4:]
    return '****'

def anonymize_subscriber(subscriber: dict) -> dict:
    """Remove/mask PII from subscriber data."""
    return {
        'subscriber_id_hash': hash_id(subscriber['subscriber_id']),
        'phone_masked': mask_phone_number(subscriber['phone_number']),
        'plan_type': subscriber['plan_type'],  # Non-PII allowed
        # Omit: full phone, address, location, etc.
    }

# Always anonymize before returning
@app.get("/subscriber/{id}")
async def get_subscriber(id: str, current_user: User):
    # Verify authorization
    if not has_permission(current_user, 'view_subscriber'):
        raise HTTPException(403, "Not authorized")

    subscriber = await db.get_subscriber(id)
    return anonymize_subscriber(subscriber)'''

        return '''// Protect subscriber PII before exposure

function maskPhoneNumber(phone: string): string {
  if (phone.length >= 4) {
    return '*'.repeat(phone.length - 4) + phone.slice(-4);
  }
  return '****';
}

function anonymizeSubscriber(subscriber: Subscriber): SafeSubscriber {
  return {
    subscriberIdHash: hashId(subscriber.subscriberId),
    phoneMasked: maskPhoneNumber(subscriber.phoneNumber),
    planType: subscriber.planType,  // Non-PII allowed
    // Omit: full phone, address, location, etc.
  };
}

// Always anonymize before returning
app.get('/subscriber/:id', async (req, res) => {
  // Verify authorization
  if (!hasPermission(req.user, 'view_subscriber')) {
    return res.status(403).json({ error: 'Not authorized' });
  }

  const subscriber = await db.getSubscriber(req.params.id);
  res.json(anonymizeSubscriber(subscriber));
});'''
