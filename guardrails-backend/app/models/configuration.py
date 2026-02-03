from sqlalchemy import Column, String, DateTime, JSON, Boolean
from sqlalchemy.sql import func
import uuid

from app.models.database import Base


class ConfigurationModel(Base):
    """Configuration table for org/repo-level settings."""

    __tablename__ = "configurations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    org = Column(String(255), nullable=False, index=True)
    repo = Column(String(255), nullable=True, index=True)  # NULL for org-level config
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    enforcement_mode = Column(String(50), default="warning")  # advisory, warning, blocking
    enabled_rule_packs = Column(JSON, nullable=True)  # Array of pack names
    custom_rules = Column(JSON, nullable=True)  # Array of rule IDs
    allowed_licenses = Column(JSON, nullable=True)  # Array of SPDX IDs
    blocked_licenses = Column(JSON, nullable=True)  # Array of SPDX IDs
    naming_conventions = Column(JSON, nullable=True)  # Naming config object
    logging_requirements = Column(JSON, nullable=True)  # Logging config object
    error_handling_patterns = Column(JSON, nullable=True)  # Error handling config object
    security_config = Column(JSON, nullable=True)  # Security config object
    copilot_config = Column(JSON, nullable=True)  # Copilot-specific config
    include_patterns = Column(JSON, nullable=True)  # File patterns to include
    exclude_patterns = Column(JSON, nullable=True)  # File patterns to exclude
    override_allowed = Column(Boolean, default=True)
    override_approvers = Column(JSON, nullable=True)  # Array of GitHub usernames
    extra_data = Column(JSON, nullable=True)  # Extensibility

    def __repr__(self):
        return f"<Configuration {self.id} {self.org}/{self.repo or '*'}>"
