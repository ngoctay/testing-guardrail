from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime
import io
import csv
import json

from app.models.database import get_db
from app.schemas.audit import AuditLog, AuditCreate, AuditQuery
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("", response_model=List[AuditLog])
async def query_audit_logs(
    org: Optional[str] = None,
    repo: Optional[str] = None,
    event_type: Optional[str] = None,
    action_taken: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """
    Query audit logs with various filters.
    """
    service = AuditService(db)
    query = AuditQuery(
        org=org,
        repo=repo,
        event_type=event_type,
        action_taken=action_taken,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )
    return await service.query_logs(query)


@router.get("/export")
async def export_audit_logs(
    format: str = Query(default="csv", regex="^(csv|json)$"),
    org: Optional[str] = None,
    repo: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Export audit logs in CSV or JSON format.
    Suitable for compliance and audit teams.
    """
    service = AuditService(db)
    query = AuditQuery(
        org=org,
        repo=repo,
        start_date=start_date,
        end_date=end_date,
        limit=10000,  # Max export limit
        offset=0,
    )
    logs = await service.query_logs(query)

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "id", "timestamp", "event_type", "org", "repo",
                "pr_number", "commit_sha", "author", "action_taken",
                "violations_count", "resolution_state"
            ]
        )
        writer.writeheader()
        for log in logs:
            writer.writerow({
                "id": log.id,
                "timestamp": log.timestamp.isoformat(),
                "event_type": log.event_type,
                "org": log.org,
                "repo": log.repo,
                "pr_number": log.pr_number,
                "commit_sha": log.commit_sha,
                "author": log.author,
                "action_taken": log.action_taken,
                "violations_count": log.violations_count,
                "resolution_state": log.resolution_state,
            })
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"}
        )
    else:
        return StreamingResponse(
            iter([json.dumps([log.model_dump() for log in logs], default=str)]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=audit_logs.json"}
        )


@router.post("", response_model=AuditLog, status_code=201)
async def create_audit_entry(
    entry: AuditCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create an audit log entry.
    Used internally by the system to record violations and actions.
    """
    service = AuditService(db)
    return await service.create_log(entry)
