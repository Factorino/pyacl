from dataclasses import dataclass, field
from enum import StrEnum, auto, unique
from typing import ClassVar, NewType, Sequence, cast
from uuid import UUID

from acl import ActionSet, Policy, RolePermissions, acl_entity, allow
from models.tag import Tag
from models.user import User, UserId, UserRole


@unique
class MediaType(StrEnum):
    PHOTO = auto()
    VIDEO = auto()
    GIF = auto()

    def __str__(self) -> str:
        name: str = cast(str, self.name)
        return name.lower().replace("_", " ")


MediaId = NewType("MediaId", UUID)


@acl_entity(resource=True)
@dataclass(kw_only=True)
class Media:
    id: MediaId
    path: str
    name: str
    description: str | None = None
    type: MediaType

    owner_id: UserId
    tags: Sequence[Tag] = field(default_factory=list)


class MediaAction(ActionSet, entity=Media):
    READ = auto()
    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()
    SHARE = auto()


class MediaPolicy(Policy, resource=Media, actions=MediaAction):
    roles: ClassVar[RolePermissions[UserRole, MediaAction] | None] = RolePermissions(
        {
            UserRole.USER: MediaAction.READ | MediaAction.CREATE,
            UserRole.MODER: MediaAction.DELETE,
            UserRole.ADMIN: MediaAction.UPDATE | MediaAction.SHARE,
        },
        inherit=True,
    )

    @allow(MediaAction.UPDATE)
    def can_update(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id

    @allow(MediaAction.DELETE)
    def can_delete(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id

    @allow(MediaAction.SHARE)
    def can_share(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id
