import pytest
from app.rules.industry.healthcare import (
    PHILoggingRule,
    EncryptionRequiredRule,
    HIPAAAuditTrailRule,
)
from app.rules.industry.telecom import (
    DataRetentionRule,
    SubscriberPrivacyRule,
)
from app.rules.industry.government import (
    AccessControlRule,
    FedRAMPAuditLoggingRule,
    EncryptionStandardsRule,
)
from app.rules.base import Severity, Category


class TestPHILoggingRule:
    """Tests for PHI Logging Prevention rule."""

    @pytest.fixture
    def rule(self):
        return PHILoggingRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "HIPAA-001"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY

    def test_detects_phi_in_print(self, rule):
        """Test detection of PHI in print statements."""
        code = '''
def process_patient(patient_name):
    print(f"Processing patient: {patient_name}")
'''
        results = rule.check(code, "processor.py", "python")
        assert len(results) >= 1
        assert any("PHI" in r.title for r in results)

    def test_detects_phi_in_console_log(self, rule):
        """Test detection of PHI in console.log."""
        code = '''
function processPatient(patientName, ssn) {
    console.log("Patient SSN:", ssn);
}
'''
        results = rule.check(code, "processor.js", "javascript")
        assert len(results) >= 1

    def test_no_violation_without_phi(self, rule):
        """Test no violation when no PHI is logged."""
        code = '''
def process_order(order_id):
    print(f"Processing order: {order_id}")
'''
        results = rule.check(code, "orders.py", "python")
        assert len(results) == 0


class TestEncryptionRequiredRule:
    """Tests for PHI Encryption Required rule."""

    @pytest.fixture
    def rule(self):
        return EncryptionRequiredRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "HIPAA-002"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY

    def test_detects_unencrypted_storage(self, rule):
        """Test detection of unencrypted PHI storage."""
        code = '''
def save_patient_record(patient_data):
    with open("patients.json", "w") as f:
        json.dump(patient_data, f)
'''
        results = rule.check(code, "storage.py", "python")
        # Should flag potential unencrypted storage
        assert len(results) >= 1

    def test_detects_localstorage_phi(self, rule):
        """Test detection of PHI in localStorage."""
        code = '''
function savePatientData(data) {
    localStorage.setItem("patient_record", JSON.stringify(data));
}
'''
        results = rule.check(code, "storage.js", "javascript")
        assert len(results) >= 1


class TestHIPAAAuditTrailRule:
    """Tests for PHI Audit Trail rule."""

    @pytest.fixture
    def rule(self):
        return HIPAAAuditTrailRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "HIPAA-003"
        assert rule.severity == Severity.HIGH
        assert rule.category == Category.SECURITY

    def test_detects_missing_audit(self, rule):
        """Test detection of PHI access without audit."""
        code = '''
def get_patient_record(patient_id):
    return database.query(f"SELECT * FROM patients WHERE id = {patient_id}")
'''
        results = rule.check(code, "records.py", "python")
        assert len(results) >= 1
        assert any("audit" in r.title.lower() for r in results)

    def test_no_violation_with_audit(self, rule):
        """Test no violation when audit logging is present."""
        code = '''
def get_patient_record(patient_id, user_id):
    audit_log.info("PHI access", patient_id=patient_id, user=user_id)
    return database.get_patient(patient_id)
'''
        results = rule.check(code, "records.py", "python")
        assert len(results) == 0


class TestDataRetentionRule:
    """Tests for Telecom Data Retention rule."""

    @pytest.fixture
    def rule(self):
        return DataRetentionRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "TEL-001"
        assert rule.severity == Severity.HIGH
        assert rule.category == Category.SECURITY

    def test_detects_cdr_without_retention(self, rule):
        """Test detection of CDR storage without retention."""
        code = '''
def save_call_record(call_data):
    call_record = CallRecord(**call_data)
    call_record.save()
'''
        results = rule.check(code, "cdr.py", "python")
        assert len(results) >= 1

    def test_no_violation_with_ttl(self, rule):
        """Test no violation when TTL is specified."""
        code = '''
def save_call_record(call_data):
    call_record = CallRecord(**call_data)
    call_record.ttl = datetime.now() + timedelta(days=365)
    call_record.save()
'''
        results = rule.check(code, "cdr.py", "python")
        # Should not flag when retention/TTL is mentioned
        assert len(results) == 0


class TestSubscriberPrivacyRule:
    """Tests for Subscriber Privacy rule."""

    @pytest.fixture
    def rule(self):
        return SubscriberPrivacyRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "TEL-002"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY

    def test_detects_phone_number_exposure(self, rule):
        """Test detection of phone number exposure."""
        code = '''
def get_subscriber(id):
    subscriber = db.get_subscriber(id)
    return subscriber  # Returns full phone_number
'''
        results = rule.check(code, "api.py", "python")
        assert len(results) >= 1

    def test_no_violation_with_masking(self, rule):
        """Test no violation when data is masked."""
        code = '''
def get_subscriber(id):
    subscriber = db.get_subscriber(id)
    return mask(subscriber)  # Mask sensitive fields
'''
        results = rule.check(code, "api.py", "python")
        assert len(results) == 0


class TestAccessControlRule:
    """Tests for FedRAMP Access Control rule."""

    @pytest.fixture
    def rule(self):
        return AccessControlRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "FED-001"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY

    def test_detects_unprotected_endpoint(self, rule):
        """Test detection of unprotected endpoint."""
        code = '''
@app.get("/admin/users")
async def list_users():
    return await db.get_all_users()
'''
        results = rule.check(code, "api.py", "python")
        assert len(results) >= 1
        assert any("access control" in r.title.lower() for r in results)

    def test_no_violation_with_auth(self, rule):
        """Test no violation when auth is present."""
        code = '''
@app.get("/admin/users")
@require_auth
async def list_users(current_user = Depends(get_current_user)):
    return await db.get_all_users()
'''
        results = rule.check(code, "api.py", "python")
        assert len(results) == 0


class TestFedRAMPAuditLoggingRule:
    """Tests for FedRAMP Audit Logging rule."""

    @pytest.fixture
    def rule(self):
        return FedRAMPAuditLoggingRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "FED-002"
        assert rule.severity == Severity.HIGH
        assert rule.category == Category.SECURITY

    def test_detects_login_without_audit(self, rule):
        """Test detection of login without audit logging."""
        code = '''
async def login(credentials):
    user = await authenticate(credentials)
    if user:
        return create_token(user)
    raise HTTPException(401)
'''
        results = rule.check(code, "auth.py", "python")
        assert len(results) >= 1

    def test_no_violation_with_audit(self, rule):
        """Test no violation when audit logging is present."""
        code = '''
async def login(credentials):
    user = await authenticate(credentials)
    if user:
        audit_log.info("login_success", user_id=user.id)
        return create_token(user)
    audit_log.warn("login_failure", username=credentials.username)
    raise HTTPException(401)
'''
        results = rule.check(code, "auth.py", "python")
        # Should not flag when audit logging is present
        assert len(results) == 0


class TestEncryptionStandardsRule:
    """Tests for FedRAMP Encryption Standards rule."""

    @pytest.fixture
    def rule(self):
        return EncryptionStandardsRule()

    def test_rule_metadata(self, rule):
        """Test rule metadata is correct."""
        assert rule.rule_id == "FED-003"
        assert rule.severity == Severity.CRITICAL
        assert rule.category == Category.SECURITY

    def test_detects_md5(self, rule):
        """Test detection of MD5 usage."""
        code = '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
'''
        results = rule.check(code, "auth.py", "python")
        assert len(results) >= 1
        assert any("MD5" in r.title for r in results)

    def test_detects_sha1(self, rule):
        """Test detection of SHA-1 usage."""
        code = '''
const crypto = require('crypto');
const hash = crypto.createHash('sha1').update(data).digest('hex');
'''
        results = rule.check(code, "crypto.js", "javascript")
        assert len(results) >= 1
        assert any("SHA-1" in r.title or "SHA1" in r.title for r in results)

    def test_detects_des(self, rule):
        """Test detection of DES usage."""
        code = '''
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)
'''
        results = rule.check(code, "crypto.py", "python")
        assert len(results) >= 1

    def test_allows_aes256(self, rule):
        """Test that AES-256 is allowed."""
        code = '''
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cipher = Cipher(algorithms.AES256(key), modes.GCM(iv))
'''
        results = rule.check(code, "crypto.py", "python")
        # AES-256 should not be flagged
        assert not any("AES-256" in r.title for r in results)

    def test_allows_sha256(self, rule):
        """Test that SHA-256 is allowed."""
        code = '''
import hashlib

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()
'''
        results = rule.check(code, "hash.py", "python")
        # SHA-256 should not be flagged
        assert not any("SHA-256" in r.title or "SHA256" in r.title for r in results)
