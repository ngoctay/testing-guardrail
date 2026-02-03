import uuid
from typing import Optional
from datetime import datetime
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.config import RepoConfig, RepoConfigUpdate
from app.models.configuration import ConfigurationModel


class ConfigService:
    """Service for managing repository configurations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_config(
        self,
        org: str,
        repo: Optional[str] = None,
    ) -> Optional[RepoConfig]:
        """Get configuration for org/repo with fallback to org-level."""
        # Try repo-level first if repo is specified
        if repo:
            result = await self.db.execute(
                select(ConfigurationModel).where(
                    and_(
                        ConfigurationModel.org == org,
                        ConfigurationModel.repo == repo,
                    )
                )
            )
            config = result.scalar_one_or_none()
            if config:
                return self._model_to_schema(config)

        # Fall back to org-level
        result = await self.db.execute(
            select(ConfigurationModel).where(
                and_(
                    ConfigurationModel.org == org,
                    ConfigurationModel.repo.is_(None),
                )
            )
        )
        config = result.scalar_one_or_none()
        if config:
            return self._model_to_schema(config)

        return None

    async def update_config(
        self,
        org: str,
        repo: Optional[str],
        update: RepoConfigUpdate,
    ) -> RepoConfig:
        """Update or create configuration."""
        # Check if config exists
        conditions = [ConfigurationModel.org == org]
        if repo:
            conditions.append(ConfigurationModel.repo == repo)
        else:
            conditions.append(ConfigurationModel.repo.is_(None))

        result = await self.db.execute(
            select(ConfigurationModel).where(and_(*conditions))
        )
        config_model = result.scalar_one_or_none()

        if config_model:
            # Update existing
            update_data = update.model_dump(exclude_unset=True)
            for field, value in update_data.items():
                if value is not None:
                    if field == "enforcement_mode" and hasattr(value, "value"):
                        value = value.value
                    # Map schema fields to model fields
                    model_field = self._schema_to_model_field(field)
                    if hasattr(config_model, model_field):
                        if hasattr(value, "model_dump"):
                            value = value.model_dump()
                        setattr(config_model, model_field, value)

            config_model.updated_at = datetime.utcnow()
        else:
            # Create new
            config_model = ConfigurationModel(
                id=str(uuid.uuid4()),
                org=org,
                repo=repo,
                enforcement_mode=update.enforcement_mode.value if update.enforcement_mode else "warning",
                enabled_rule_packs=update.enabled_rule_packs,
                custom_rules=update.custom_rules,
                allowed_licenses=update.license.allowed if update.license else None,
                blocked_licenses=update.license.blocked if update.license else None,
                naming_conventions=update.naming.model_dump() if update.naming else None,
                logging_requirements=update.logging.model_dump() if update.logging else None,
                error_handling_patterns=update.error_handling.model_dump() if update.error_handling else None,
                security_config=update.security.model_dump() if update.security else None,
                copilot_config=update.copilot.model_dump() if update.copilot else None,
                include_patterns=update.include_patterns,
                exclude_patterns=update.exclude_patterns,
                override_allowed=update.override.enabled if update.override else True,
                override_approvers=update.override.approvers if update.override else None,
                extra_data=update.extra_data,
            )
            self.db.add(config_model)

        await self.db.commit()
        await self.db.refresh(config_model)
        return self._model_to_schema(config_model)

    def _schema_to_model_field(self, field: str) -> str:
        """Map schema field names to model field names."""
        mapping = {
            "enabled_rule_packs": "enabled_rule_packs",
            "custom_rules": "custom_rules",
            "enforcement_mode": "enforcement_mode",
            "include_patterns": "include_patterns",
            "exclude_patterns": "exclude_patterns",
            "extra_data": "extra_data",
        }
        return mapping.get(field, field)

    def _model_to_schema(self, model: ConfigurationModel) -> RepoConfig:
        """Convert database model to schema."""
        from app.schemas.config import (
            EnforcementMode,
            OverrideConfig,
            SecurityConfig,
            NamingConfig,
            LoggingConfig,
            ErrorHandlingConfig,
            LicenseConfig,
            CopilotConfig,
        )

        return RepoConfig(
            id=model.id,
            org=model.org,
            repo=model.repo,
            created_at=model.created_at,
            updated_at=model.updated_at,
            enforcement_mode=EnforcementMode(model.enforcement_mode),
            enabled_rule_packs=model.enabled_rule_packs or ["default-security", "enterprise-standards"],
            custom_rules=model.custom_rules or [],
            override=OverrideConfig(
                enabled=model.override_allowed,
                approvers=model.override_approvers or [],
            ),
            security=SecurityConfig(**(model.security_config or {})),
            naming=NamingConfig(**(model.naming_conventions or {})),
            logging=LoggingConfig(**(model.logging_requirements or {})),
            error_handling=ErrorHandlingConfig(**(model.error_handling_patterns or {})),
            license=LicenseConfig(
                allowed=model.allowed_licenses or ["MIT", "Apache-2.0", "BSD-3-Clause"],
                blocked=model.blocked_licenses or ["GPL-3.0", "AGPL-3.0"],
            ),
            copilot=CopilotConfig(**(model.copilot_config or {})),
            include_patterns=model.include_patterns or ["src/**/*", "lib/**/*"],
            exclude_patterns=model.exclude_patterns or ["node_modules/**", "dist/**"],
            extra_data=model.extra_data,
        )
