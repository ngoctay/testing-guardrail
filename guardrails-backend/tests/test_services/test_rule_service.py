import pytest
from unittest.mock import AsyncMock, MagicMock
from app.services.rule_service import RuleService, BUILT_IN_PACKS


class TestBuiltInPacks:
    """Tests for built-in rule packs configuration."""

    def test_built_in_packs_exist(self):
        """Test that built-in packs are defined."""
        assert "default-security" in BUILT_IN_PACKS
        assert "enterprise-standards" in BUILT_IN_PACKS
        assert "healthcare" in BUILT_IN_PACKS
        assert "telecom" in BUILT_IN_PACKS
        assert "government" in BUILT_IN_PACKS

    def test_default_security_pack_rules(self):
        """Test default-security pack has expected rules."""
        pack = BUILT_IN_PACKS["default-security"]
        assert pack["display_name"] == "Default Security"
        assert "SEC-001-hardcoded-secrets" in pack["rules"]
        assert "SEC-002-sql-injection" in pack["rules"]
        assert "SEC-003-command-injection" in pack["rules"]
        assert "SEC-004-path-traversal" in pack["rules"]

    def test_enterprise_standards_pack_rules(self):
        """Test enterprise-standards pack has expected rules."""
        pack = BUILT_IN_PACKS["enterprise-standards"]
        assert pack["display_name"] == "Enterprise Standards"
        assert "STD-001-naming-conventions" in pack["rules"]
        assert "STD-002-logging-requirements" in pack["rules"]
        assert "STD-003-error-handling" in pack["rules"]

    def test_healthcare_pack_rules(self):
        """Test healthcare (HIPAA) pack has expected rules."""
        pack = BUILT_IN_PACKS["healthcare"]
        assert pack["display_name"] == "Healthcare (HIPAA)"
        assert pack["category"] == "healthcare"
        assert "HIPAA-001-phi-logging" in pack["rules"]
        assert "HIPAA-002-encryption-required" in pack["rules"]
        assert "HIPAA-003-audit-trail" in pack["rules"]

    def test_telecom_pack_rules(self):
        """Test telecom pack has expected rules."""
        pack = BUILT_IN_PACKS["telecom"]
        assert pack["display_name"] == "Telecom"
        assert pack["category"] == "telecom"
        assert "TEL-001-data-retention" in pack["rules"]
        assert "TEL-002-subscriber-privacy" in pack["rules"]

    def test_government_pack_rules(self):
        """Test government (FedRAMP) pack has expected rules."""
        pack = BUILT_IN_PACKS["government"]
        assert pack["display_name"] == "Government (FedRAMP)"
        assert pack["category"] == "government"
        assert "FED-001-access-control" in pack["rules"]
        assert "FED-002-audit-logging" in pack["rules"]
        assert "FED-003-encryption-standards" in pack["rules"]

    def test_all_packs_have_required_fields(self):
        """Test all packs have required configuration fields."""
        for name, pack in BUILT_IN_PACKS.items():
            assert "display_name" in pack, f"{name} missing display_name"
            assert "description" in pack, f"{name} missing description"
            assert "category" in pack, f"{name} missing category"
            assert "rules" in pack, f"{name} missing rules"
            assert len(pack["rules"]) > 0, f"{name} has no rules"


class TestRuleService:
    """Tests for the RuleService."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        db = AsyncMock()
        db.add = MagicMock()
        db.commit = AsyncMock()
        db.refresh = AsyncMock()
        db.delete = AsyncMock()
        return db

    @pytest.fixture
    def rule_service(self, mock_db):
        """Create a rule service instance."""
        return RuleService(mock_db)

    @pytest.mark.asyncio
    async def test_list_packs(self, rule_service):
        """Test listing all rule packs."""
        packs = await rule_service.list_packs()

        assert len(packs) == len(BUILT_IN_PACKS)

        pack_names = [p.name for p in packs]
        assert "default-security" in pack_names
        assert "enterprise-standards" in pack_names
        assert "healthcare" in pack_names
        assert "telecom" in pack_names
        assert "government" in pack_names

    @pytest.mark.asyncio
    async def test_list_packs_has_metadata(self, rule_service):
        """Test that packs have complete metadata."""
        packs = await rule_service.list_packs()

        for pack in packs:
            assert pack.name is not None
            assert pack.display_name is not None
            assert pack.description is not None
            assert pack.category is not None
            assert pack.rule_count > 0
            assert len(pack.rules) > 0

    @pytest.mark.asyncio
    async def test_enable_pack_valid(self, rule_service):
        """Test enabling a valid pack."""
        # Should not raise
        await rule_service.enable_pack("default-security", "test-org")
        await rule_service.enable_pack("healthcare", "test-org", "test-repo")

    @pytest.mark.asyncio
    async def test_enable_pack_invalid(self, rule_service):
        """Test enabling an invalid pack raises error."""
        with pytest.raises(ValueError, match="Unknown rule pack"):
            await rule_service.enable_pack("nonexistent-pack", "test-org")

    @pytest.mark.asyncio
    async def test_list_rules_empty_db(self, rule_service, mock_db):
        """Test listing rules with empty database."""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)

        rules = await rule_service.list_rules()
        assert rules == []

    @pytest.mark.asyncio
    async def test_get_rule_not_found(self, rule_service, mock_db):
        """Test getting a non-existent rule."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)

        rule = await rule_service.get_rule("nonexistent")
        assert rule is None

    @pytest.mark.asyncio
    async def test_delete_rule_not_found(self, rule_service, mock_db):
        """Test deleting a non-existent rule."""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)

        result = await rule_service.delete_rule("nonexistent")
        assert result is False
