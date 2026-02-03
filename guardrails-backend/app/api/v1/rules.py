from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from app.models.database import get_db
from app.schemas.rule import Rule, RuleCreate, RuleUpdate, RulePack
from app.services.rule_service import RuleService

router = APIRouter()


@router.get("", response_model=List[Rule])
async def list_rules(
    category: Optional[str] = None,
    enabled: Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    List all available rules.
    Filter by category (security, standards, license) or enabled status.
    """
    service = RuleService(db)
    return await service.list_rules(category=category, enabled=enabled)


@router.post("", response_model=Rule, status_code=201)
async def create_rule(
    rule: RuleCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Create a new custom rule.
    """
    service = RuleService(db)
    return await service.create_rule(rule)


@router.get("/{rule_id}", response_model=Rule)
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Get a specific rule by ID.
    """
    service = RuleService(db)
    rule = await service.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=Rule)
async def update_rule(
    rule_id: str,
    rule: RuleUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Update an existing rule.
    """
    service = RuleService(db)
    updated = await service.update_rule(rule_id, rule)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    return updated


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Delete a rule.
    """
    service = RuleService(db)
    deleted = await service.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")


@router.get("/packs", response_model=List[RulePack])
async def list_rule_packs(
    db: AsyncSession = Depends(get_db),
):
    """
    List all available rule packs.
    """
    service = RuleService(db)
    return await service.list_packs()


@router.post("/packs/{pack_name}/enable", status_code=204)
async def enable_rule_pack(
    pack_name: str,
    org: str,
    repo: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Enable a rule pack for an organization or repository.
    """
    service = RuleService(db)
    await service.enable_pack(pack_name, org, repo)
