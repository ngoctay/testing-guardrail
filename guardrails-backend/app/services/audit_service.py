import uuid
from typing import Optional
from datetime import datetime
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.audit import AuditLog, AuditCreate, AuditQuery
from app.models.audit_log import AuditLogModel


class AuditService:
    """Service for managing audit logs."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def query_logs(self, query: AuditQuery) -> list[AuditLog]:
        """Query audit logs with filters."""
        stmt = select(AuditLogModel)

        conditions = []
        if query.org:
            conditions.append(AuditLogModel.org == query.org)
        if query.repo:
            conditions.append(AuditLogModel.repo == query.repo)
        if query.event_type:
            conditions.append(AuditLogModel.event_type == query.event_type.value)
        if query.action_taken:
            conditions.append(AuditLogModel.action_taken == query.action_taken.value)
        if query.start_date:
            conditions.append(AuditLogModel.timestamp >= query.start_date)
        if query.end_date:
            conditions.append(AuditLogModel.timestamp <= query.end_date)

        if conditions:
            stmt = stmt.where(and_(*conditions))

        stmt = stmt.order_by(AuditLogModel.timestamp.desc())
        stmt = stmt.offset(query.offset).limit(query.limit)

        result = await self.db.execute(stmt)
        logs = result.scalars().all()

        return [self._model_to_schema(log) for log in logs]

    async def create_log(self, entry: AuditCreate) -> AuditLog:
        """Create a new audit log entry."""
        log_model = AuditLogModel(
            id=str(uuid.uuid4()),
            event_type=entry.event_type.value,
            org=entry.org,
            repo=entry.repo,
            pr_number=entry.pr_number,
            commit_sha=entry.commit_sha,
            author=entry.author,
            action_taken=entry.action_taken.value,
            scan_id=entry.scan_id,
            violations_count=entry.violations_count,
            details=entry.details,
            resolution_state=entry.resolution_state.value,
            resolved_by=entry.resolved_by,
            resolved_at=entry.resolved_at,
            extra_data=entry.extra_data,
        )
        self.db.add(log_model)
        await self.db.commit()
        await self.db.refresh(log_model)
        return self._model_to_schema(log_model)

    async def update_resolution(
        self,
        log_id: str,
        resolution_state: str,
        resolved_by: str,
    ) -> Optional[AuditLog]:
        """Update resolution state of an audit log."""
        result = await self.db.execute(
            select(AuditLogModel).where(AuditLogModel.id == log_id)
        )
        log_model = result.scalar_one_or_none()
        if not log_model:
            return None

        log_model.resolution_state = resolution_state
        log_model.resolved_by = resolved_by
        log_model.resolved_at = datetime.utcnow()
        await self.db.commit()
        await self.db.refresh(log_model)
        return self._model_to_schema(log_model)

    def _model_to_schema(self, model: AuditLogModel) -> AuditLog:
        """Convert database model to schema."""
        from app.schemas.audit import EventType, ActionTaken, ResolutionState

        return AuditLog(
            id=model.id,
            timestamp=model.timestamp,
            event_type=EventType(model.event_type),
            org=model.org,
            repo=model.repo,
            pr_number=model.pr_number,
            commit_sha=model.commit_sha,
            author=model.author,
            action_taken=ActionTaken(model.action_taken),
            scan_id=model.scan_id,
            violations_count=model.violations_count,
            details=model.details,
            resolution_state=ResolutionState(model.resolution_state),
            resolved_by=model.resolved_by,
            resolved_at=model.resolved_at,
            extra_data=model.extra_data,
        )
