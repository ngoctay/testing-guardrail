from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime
from enum import Enum


class EventType(str, Enum):
    SCAN = "scan"
    VIOLATION = "violation"
    OVERRIDE = "override"
    CONFIG_CHANGE = "config_change"


class ActionTaken(str, Enum):
    ADVISORY = "advisory"
    WARNING = "warning"
    BLOCKED = "blocked"
    OVERRIDE = "override"


class ResolutionState(str, Enum):
    PENDING = "pending"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class AuditBase(BaseModel):
    event_type: EventType
    org: str
    repo: str
    pr_number: Optional[int] = None
    commit_sha: Optional[str] = None
    author: Optional[str] = None
    action_taken: ActionTaken
    scan_id: Optional[str] = None
    violations_count: int = 0
    details: Optional[dict[str, Any]] = None
    resolution_state: ResolutionState = ResolutionState.PENDING
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    extra_data: Optional[dict[str, Any]] = None


class AuditCreate(AuditBase):
    pass


class AuditLog(AuditBase):
    id: str
    timestamp: datetime

    class Config:
        from_attributes = True


class AuditQuery(BaseModel):
    org: Optional[str] = None
    repo: Optional[str] = None
    event_type: Optional[EventType] = None
    action_taken: Optional[ActionTaken] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, le=10000)
    offset: int = Field(default=0, ge=0)
