from fastapi import APIRouter

from app.api.v1.scan import router as scan_router
from app.api.v1.analyze import router as analyze_router
from app.api.v1.license import router as license_router
from app.api.v1.rules import router as rules_router
from app.api.v1.audit import router as audit_router
from app.api.v1.config import router as config_router

api_router = APIRouter()

api_router.include_router(scan_router, prefix="/scan", tags=["Scan"])
api_router.include_router(analyze_router, prefix="/analyze", tags=["Analyze"])
api_router.include_router(license_router, prefix="/license", tags=["License"])
api_router.include_router(rules_router, prefix="/rules", tags=["Rules"])
api_router.include_router(audit_router, prefix="/audit", tags=["Audit"])
api_router.include_router(config_router, prefix="/config", tags=["Config"])
