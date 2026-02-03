import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.rule import Rule, RuleCreate, RuleUpdate, RulePack
from app.models.rule import RuleModel


# Built-in rule packs
BUILT_IN_PACKS = {
    "default-security": {
        "display_name": "Default Security",
        "description": "Basic security rules for common vulnerabilities",
        "category": "default",
        "rules": [
            "SEC-001-hardcoded-secrets",
            "SEC-002-sql-injection",
            "SEC-003-command-injection",
            "SEC-004-path-traversal",
            "SEC-005-xss",
        ],
    },
    "enterprise-standards": {
        "display_name": "Enterprise Standards",
        "description": "Common enterprise coding standards",
        "category": "default",
        "rules": [
            "STD-001-naming-conventions",
            "STD-002-logging-requirements",
            "STD-003-error-handling",
        ],
    },
    "healthcare": {
        "display_name": "Healthcare (HIPAA)",
        "description": "HIPAA compliance rules for healthcare applications",
        "category": "healthcare",
        "rules": [
            "HIPAA-001-phi-logging",
            "HIPAA-002-encryption-required",
            "HIPAA-003-audit-trail",
        ],
    },
    "telecom": {
        "display_name": "Telecom",
        "description": "Telecom industry compliance rules",
        "category": "telecom",
        "rules": [
            "TEL-001-data-retention",
            "TEL-002-subscriber-privacy",
        ],
    },
    "government": {
        "display_name": "Government (FedRAMP)",
        "description": "FedRAMP compliance rules for government applications",
        "category": "government",
        "rules": [
            "FED-001-access-control",
            "FED-002-audit-logging",
            "FED-003-encryption-standards",
        ],
    },
}


class RuleService:
    """Service for managing rules and rule packs."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_rules(
        self,
        category: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> list[Rule]:
        """List all rules with optional filters."""
        query = select(RuleModel)

        conditions = []
        if category:
            conditions.append(RuleModel.category == category)
        if enabled is not None:
            conditions.append(RuleModel.enabled == enabled)

        if conditions:
            query = query.where(and_(*conditions))

        result = await self.db.execute(query)
        rules = result.scalars().all()

        return [self._model_to_schema(r) for r in rules]

    async def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get a specific rule by ID."""
        result = await self.db.execute(
            select(RuleModel).where(RuleModel.id == rule_id)
        )
        rule = result.scalar_one_or_none()
        if rule:
            return self._model_to_schema(rule)
        return None

    async def create_rule(self, rule: RuleCreate) -> Rule:
        """Create a new custom rule."""
        rule_model = RuleModel(
            id=str(uuid.uuid4()),
            name=rule.name,
            description=rule.description,
            category=rule.category.value,
            severity=rule.severity.value,
            enabled=rule.enabled,
            rule_type=rule.rule_type.value,
            languages=rule.languages,
            pattern=rule.pattern,
            ai_prompt=rule.ai_prompt,
            owasp_mapping=rule.owasp_mapping,
            cwe_id=rule.cwe_id,
            fix_suggestion=rule.fix_suggestion,
            references=rule.references,
            org=rule.org,
            repo=rule.repo,
            rule_pack=rule.rule_pack,
        )
        self.db.add(rule_model)
        await self.db.commit()
        await self.db.refresh(rule_model)
        return self._model_to_schema(rule_model)

    async def update_rule(
        self,
        rule_id: str,
        rule: RuleUpdate,
    ) -> Optional[Rule]:
        """Update an existing rule."""
        result = await self.db.execute(
            select(RuleModel).where(RuleModel.id == rule_id)
        )
        rule_model = result.scalar_one_or_none()
        if not rule_model:
            return None

        update_data = rule.model_dump(exclude_unset=True)
        for field, value in update_data.items():
            if value is not None:
                if hasattr(value, "value"):  # Enum
                    value = value.value
                setattr(rule_model, field, value)

        rule_model.updated_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(rule_model)
        return self._model_to_schema(rule_model)

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule."""
        result = await self.db.execute(
            select(RuleModel).where(RuleModel.id == rule_id)
        )
        rule_model = result.scalar_one_or_none()
        if not rule_model:
            return False

        await self.db.delete(rule_model)
        await self.db.commit()
        return True

    async def list_packs(self) -> list[RulePack]:
        """List all available rule packs."""
        packs = []
        for name, config in BUILT_IN_PACKS.items():
            packs.append(RulePack(
                name=name,
                display_name=config["display_name"],
                description=config["description"],
                category=config["category"],
                rule_count=len(config["rules"]),
                rules=config["rules"],
                enabled=False,  # Would check against configuration
            ))
        return packs

    async def enable_pack(
        self,
        pack_name: str,
        org: str,
        repo: Optional[str] = None,
    ) -> None:
        """Enable a rule pack for an org/repo."""
        # This would update the configuration table
        # For now, just validate the pack exists
        if pack_name not in BUILT_IN_PACKS:
            raise ValueError(f"Unknown rule pack: {pack_name}")

        # In production, update the configuration
        pass

    def _model_to_schema(self, model: RuleModel) -> Rule:
        """Convert database model to schema."""
        from app.schemas.rule import RuleType, RuleSeverity, RuleCategory

        return Rule(
            id=model.id,
            name=model.name,
            description=model.description,
            category=RuleCategory(model.category),
            severity=RuleSeverity(model.severity),
            enabled=model.enabled,
            rule_type=RuleType(model.rule_type),
            languages=model.languages or [],
            pattern=model.pattern,
            ai_prompt=model.ai_prompt,
            owasp_mapping=model.owasp_mapping,
            cwe_id=model.cwe_id,
            fix_suggestion=model.fix_suggestion,
            references=model.references or [],
            org=model.org,
            repo=model.repo,
            rule_pack=model.rule_pack,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )
