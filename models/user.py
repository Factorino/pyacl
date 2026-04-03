from dataclasses import dataclass
from enum import Flag, auto, unique
from typing import ClassVar, NewType, cast
from uuid import UUID

from acl import ActionSet, Policy, RolePermissions, acl_entity, allow, deny


@unique
class UserRole(Flag):
    USER = auto()
    MODER = auto()
    ADMIN = auto()

    def __str__(self) -> str:
        name: str = cast(str, self.name)
        return name.lower().replace("_", " ")


UserId = NewType("UserId", UUID)


@acl_entity(subject=True, resource=True)
@dataclass(kw_only=True)
class User:
    id: UserId
    username: str
    password_hash: bytes
    role: UserRole = UserRole.USER


class UserAction(ActionSet, entity=User):
    READ = auto()
    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()


class UserPolicy(Policy, resource=User, actions=UserAction):
    roles: ClassVar[RolePermissions[UserRole, UserAction] | None] = RolePermissions(
        {
            UserRole.MODER: UserAction.READ | UserAction.UPDATE,
            UserRole.ADMIN: UserAction.CREATE | UserAction.DELETE,
        },
        inherit=True,
    )

    @allow(UserAction.READ)
    def can_read(self, subject: User, resource: User) -> bool:
        return subject.id == resource.id

    @allow(UserAction.UPDATE)
    def can_update(self, subject: User, resource: User) -> bool:
        return subject.id == resource.id

    @deny(UserAction.UPDATE)
    def cannot_update_admin(self, subject: User, resource: User) -> bool:
        return subject.role == UserRole.MODER and resource.role == UserRole.ADMIN

    @allow(UserAction.DELETE)
    def can_delete(self, subject: User, resource: User) -> bool:
        return subject.id == resource.id
