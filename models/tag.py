from dataclasses import dataclass
from enum import auto
from typing import ClassVar, NewType
from uuid import UUID

from acl import ActionSet, Policy, RolePermissions, acl_entity, allow
from models.user import User, UserId, UserRole

TagId = NewType("TagId", UUID)


@acl_entity(resource=True)
@dataclass(kw_only=True)
class Tag:
    id: TagId
    name: str
    description: str | None = None

    owner_id: UserId


class TagAction(ActionSet, entity=Tag):
    READ = auto()
    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()


class TagPolicy(Policy, resource=Tag, actions=TagAction):
    roles: ClassVar[RolePermissions[UserRole, TagAction] | None] = RolePermissions(
        {
            UserRole.USER: TagAction.READ | TagAction.CREATE,
            UserRole.MODER: TagAction.UPDATE | TagAction.DELETE,
        },
        inherit=True,
    )

    @allow(TagAction.UPDATE)
    def can_update(self, subject: User, resource: Tag) -> bool:
        return subject.id == resource.owner_id

    @allow(TagAction.DELETE)
    def can_delete(self, subject: User, resource: Tag) -> bool:
        return subject.id == resource.owner_id
