from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.models.database import get_db
from app.schemas.config import RepoConfig, RepoConfigUpdate
from app.services.config_service import ConfigService

router = APIRouter()


@router.get("/{org}/{repo}", response_model=RepoConfig)
async def get_repo_config(
    org: str,
    repo: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get configuration for a specific repository.
    Falls back to organization-level config if no repo-level config exists.
    """
    service = ConfigService(db)
    config = await service.get_config(org, repo)
    if not config:
        # Return default config
        return RepoConfig(
            org=org,
            repo=repo,
            enforcement_mode="warning",
            enabled_rule_packs=["default-security", "enterprise-standards"],
        )
    return config


@router.put("/{org}/{repo}", response_model=RepoConfig)
async def update_repo_config(
    org: str,
    repo: str,
    config: RepoConfigUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update configuration for a specific repository.
    """
    service = ConfigService(db)
    return await service.update_config(org, repo, config)


@router.get("/{org}", response_model=RepoConfig)
async def get_org_config(
    org: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get organization-level configuration.
    """
    service = ConfigService(db)
    config = await service.get_config(org, None)
    if not config:
        return RepoConfig(
            org=org,
            enforcement_mode="warning",
            enabled_rule_packs=["default-security", "enterprise-standards"],
        )
    return config


@router.put("/{org}", response_model=RepoConfig)
async def update_org_config(
    org: str,
    config: RepoConfigUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update organization-level configuration.
    """
    service = ConfigService(db)
    return await service.update_config(org, None, config)
