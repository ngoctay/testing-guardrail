from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.schemas.license import LicenseRequest, LicenseResponse, SimilarityRequest, SimilarityResponse
from app.services.license_analyzer import LicenseAnalyzerService

router = APIRouter()


@router.post("/check", response_model=LicenseResponse)
async def check_license(
    request: LicenseRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Check license compliance for dependencies and code files.
    Detects restricted or incompatible licenses.
    """
    analyzer = LicenseAnalyzerService(db)
    return await analyzer.check_licenses(request)


@router.post("/similarity", response_model=SimilarityResponse)
async def check_similarity(
    request: SimilarityRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Check code similarity to detect potential IP risks.
    Identifies copied or near-duplicate code patterns.
    """
    analyzer = LicenseAnalyzerService(db)
    return await analyzer.check_similarity(request)
