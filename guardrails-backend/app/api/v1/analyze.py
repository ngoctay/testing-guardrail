from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import get_db
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse, FixRequest, FixResponse
from app.services.ai_analyzer import AIAnalyzerService

router = APIRouter()


@router.post("", response_model=AnalyzeResponse)
async def analyze_code(
    request: AnalyzeRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Perform AI-powered deep code analysis.
    Analyzes code for security, performance, and maintainability issues
    with detailed explanations.
    """
    analyzer = AIAnalyzerService(db)
    return await analyzer.analyze(request)


@router.post("/fix", response_model=FixResponse)
async def suggest_fix(
    request: FixRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Get AI-generated fix suggestions for identified issues.
    Returns compliant code fixes with reasoning.
    """
    analyzer = AIAnalyzerService(db)
    return await analyzer.suggest_fix(request)
