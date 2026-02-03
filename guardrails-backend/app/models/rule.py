from sqlalchemy import Column, String, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func
import uuid

from app.models.database import Base


class RuleModel(Base):
    """Custom rules table for user-defined rules."""

    __tablename__ = "rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=False, index=True)  # security, standards, license
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    enabled = Column(Boolean, default=True)
    rule_type = Column(String(50), nullable=False)  # regex, ast, ai, composite
    languages = Column(JSON, nullable=True)  # Array of supported languages
    pattern = Column(Text, nullable=True)  # Regex or AST pattern
    ai_prompt = Column(Text, nullable=True)  # AI analysis prompt
    owasp_mapping = Column(String(100), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    fix_suggestion = Column(Text, nullable=True)
    references = Column(JSON, nullable=True)  # Array of reference URLs
    org = Column(String(255), nullable=True, index=True)  # NULL for global rules
    repo = Column(String(255), nullable=True, index=True)  # NULL for org-level rules
    rule_pack = Column(String(100), nullable=True, index=True)  # Rule pack name

    def __repr__(self):
        return f"<Rule {self.id} {self.name} {self.category}>"
