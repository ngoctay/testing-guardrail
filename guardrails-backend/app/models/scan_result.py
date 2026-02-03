from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid

from app.models.database import Base


class ScanResultModel(Base):
    """Scan results table for storing full scan information."""

    __tablename__ = "scan_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    org = Column(String(255), nullable=False, index=True)
    repo = Column(String(255), nullable=False, index=True)
    pr_number = Column(Integer, nullable=True)
    commit_sha = Column(String(40), nullable=True)
    file_path = Column(String(1024), nullable=False)
    language = Column(String(50), nullable=True)
    scan_type = Column(String(50), nullable=False)  # security, standards, license, full
    status = Column(String(50), nullable=False)  # clean, violations_found, error
    summary = Column(JSON, nullable=False)  # JSON summary object
    violations = Column(JSON, nullable=False)  # JSON array of violations
    copilot_analysis = Column(JSON, nullable=True)  # Copilot detection results
    enforcement_action = Column(String(50), nullable=False)  # none, annotate, block
    processing_time_ms = Column(Integer, nullable=True)
    ai_model_used = Column(String(100), nullable=True)
    ai_tokens_used = Column(Integer, nullable=True)

    # Relationship to violations
    violation_records = relationship("ViolationModel", back_populates="scan_result", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanResult {self.id} {self.status} {self.file_path}>"
