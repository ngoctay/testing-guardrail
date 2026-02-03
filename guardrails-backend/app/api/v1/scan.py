from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.models.database import get_db
from app.schemas.scan import ScanRequest, ScanResponse, SecurityScanResponse, StandardsScanResponse
from app.services.scanner_service import ScannerService

router = APIRouter()


@router.post("", response_model=ScanResponse)
async def scan_code(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Perform a full code scan including security, standards, and license checks.
    """
    scanner = ScannerService(db)
    result = await scanner.scan(request)

    # Log audit in background
    background_tasks.add_task(scanner.log_audit, result)

    return result


@router.post("/security", response_model=SecurityScanResponse)
async def scan_security(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Perform security-focused scan only.
    Detects hardcoded secrets, SQL injection, insecure deserialization, etc.
    """
    scanner = ScannerService(db)
    return await scanner.scan_security(request)


@router.post("/standards", response_model=StandardsScanResponse)
async def scan_standards(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Perform enterprise standards scan only.
    Checks naming conventions, logging requirements, error handling patterns.
    """
    scanner = ScannerService(db)
    return await scanner.scan_standards(request)
