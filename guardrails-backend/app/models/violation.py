from sqlalchemy import Column, String, Integer, DateTime, Boolean, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid

from app.models.database import Base


class ViolationModel(Base):
    """Violations table for normalized querying of individual violations."""

    __tablename__ = "violations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    rule_id = Column(String(100), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    category = Column(String(50), nullable=False, index=True)  # security, standards, license
    title = Column(String(500), nullable=False)
    file_path = Column(String(1024), nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    owasp_mapping = Column(String(100), nullable=True)
    cwe_id = Column(String(50), nullable=True)
    is_ai_generated = Column(Boolean, default=False)
    resolution_state = Column(String(50), default="open")  # open, resolved, dismissed, false_positive

    # Relationship
    scan_result = relationship("ScanResultModel", back_populates="violation_records")

    def __repr__(self):
        return f"<Violation {self.id} {self.severity} {self.rule_id}>"
