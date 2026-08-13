"""Target management service with strict input validation."""

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import AddressType
from app.models.target import Target
from app.models.user import User
from app.schemas.target import TargetCreate, TargetUpdate
from app.utils.errors import ConflictError, NotFoundError
from app.utils.validation import validate_target_address


def create_target(db: Session, user: User, data: TargetCreate) -> Target:
    address, address_type = validate_target_address(data.address)

    duplicate = db.scalar(
        select(Target).where(Target.user_id == user.id, Target.address == address)
    )
    if duplicate:
        raise ConflictError("A target with this address already exists.")

    target = Target(
        user_id=user.id,
        name=data.name.strip(),
        address=address,
        address_type=address_type,
        description=data.description,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def list_targets(db: Session, user: User) -> list[Target]:
    stmt = (
        select(Target)
        .where(Target.user_id == user.id)
        .order_by(Target.created_at.desc())
    )
    return list(db.scalars(stmt).all())


def get_target(db: Session, user: User, target_id: int) -> Target:
    target = db.get(Target, target_id)
    if target is None or target.user_id != user.id:
        raise NotFoundError("Target not found.")
    return target


def update_target(
    db: Session, user: User, target_id: int, data: TargetUpdate
) -> Target:
    target = get_target(db, user, target_id)
    if data.name is not None:
        target.name = data.name.strip()
    if data.description is not None:
        target.description = data.description
    db.commit()
    db.refresh(target)
    return target


def delete_target(db: Session, user: User, target_id: int) -> None:
    target = get_target(db, user, target_id)
    db.delete(target)
    db.commit()
