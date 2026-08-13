"""Target management endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.database import get_db
from app.models.user import User
from app.schemas.target import TargetCreate, TargetOut, TargetUpdate
from app.services import target_service

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.get("", response_model=list[TargetOut])
def list_targets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list:
    return target_service.list_targets(db, current_user)


@router.post("", response_model=TargetOut, status_code=status.HTTP_201_CREATED)
def create_target(
    data: TargetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return target_service.create_target(db, current_user, data)


@router.get("/{target_id}", response_model=TargetOut)
def get_target(
    target_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return target_service.get_target(db, current_user, target_id)


@router.patch("/{target_id}", response_model=TargetOut)
def update_target(
    target_id: int,
    data: TargetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return target_service.update_target(db, current_user, target_id, data)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_target(
    target_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    target_service.delete_target(db, current_user, target_id)
