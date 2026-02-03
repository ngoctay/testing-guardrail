from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from sqlalchemy.sql import func
import uuid

from app.models.database import Base


class AuditLogModel(Base):
    """Audit log table for tracking all guardrails actions."""

    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    event_type = Column(String(50), nullable=False, index=True)  # scan, violation, override, config_change
    org = Column(String(255), nullable=False, index=True)
    repo = Column(String(255), nullable=False, index=True)
    pr_number = Column(Integer, nullable=True)
    commit_sha = Column(String(40), nullable=True)
    author = Column(String(255), nullable=True)
    action_taken = Column(String(50), nullable=False)  # advisory, warning, blocked, override
    scan_id = Column(String(36), nullable=True, index=True)
    violations_count = Column(Integer, default=0)
    details = Column(JSON, nullable=True)  # Additional data as JSON
    resolution_state = Column(String(50), default="pending")  # pending, resolved, dismissed
    resolved_by = Column(String(255), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    extra_data = Column(JSON, nullable=True)  # Extensibility

    def __repr__(self):
        return f"<AuditLog {self.id} {self.event_type} {self.org}/{self.repo}>"
