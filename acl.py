import functools
from abc import abstractmethod
from collections.abc import Callable, Hashable
from enum import Flag
from typing import Any, ClassVar, Concatenate, Sequence, cast

_SUBJECTS: set[type] = set()
_RESOURCES: set[type] = set()


def acl_entity[EntityT: Hashable](
    cls: type[EntityT] | None = None,
    *,
    subject: bool = False,
    resource: bool = False,
) -> type[EntityT] | Callable[[type[EntityT]], type[EntityT]]:
    def decorator(cls: type[EntityT]) -> type[EntityT]:
        if not subject and not resource:
            raise TypeError("acl_entity requires at least one of: subject=True, resource=True")
        if subject:
            _SUBJECTS.add(cls)
        if resource:
            _RESOURCES.add(cls)
        return cls

    if cls is not None:
        return decorator(cls)
    return decorator


class ActionSet(Flag):
    _entity: ClassVar[type]

    def __init_subclass__(
        cls,
        entity: type | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)

        if entity is not None:
            cls._entity = entity
        elif not hasattr(cls, "_entity"):
            raise TypeError(f"{cls.__name__} must define 'entity'")


class RolePermissions[RoleT: Flag, ActionT: ActionSet]:
    def __init__(
        self,
        permissions: dict[RoleT, ActionT],
        *,
        inherit: bool = False,
        role_order: Sequence[RoleT] | None = None,
    ) -> None:
        self._permissions: dict[RoleT, ActionT] = permissions
        self._inherit: bool = inherit
        # Если role_order не указан и нужно наследование,
        # порядок выводится из значений Flag по возрастанию
        self._role_order: Sequence[RoleT] | None = role_order

    @abstractmethod
    def resolve(self, role: RoleT) -> ActionT:
        raise NotImplementedError


class Policy:
    _resource: ClassVar[type]
    _actions: ClassVar[type[ActionSet]]

    roles: ClassVar[RolePermissions[Any, Any] | None] = None

    def __init_subclass__(
        cls,
        resource: type | None = None,
        actions: type[ActionSet] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)

        if resource is not None:
            cls._resource = resource
        elif not hasattr(cls, "_resource"):
            raise TypeError(f"{cls.__name__} must define 'resource'")

        if actions is not None:
            cls._actions = actions
        elif not hasattr(cls, "_actions"):
            raise TypeError(f"{cls.__name__} must define 'actions'")


type _PolicyMethod[PolicyT: Policy, **P, R] = Callable[Concatenate[PolicyT, P], R]


def allow[PolicyT: Policy, **P, R](
    *actions: ActionSet,
) -> Callable[
    [_PolicyMethod[PolicyT, P, R]],
    _PolicyMethod[PolicyT, P, R],
]:
    if not actions:
        raise ValueError("'allow' requires at least one action")

    def decorator(
        wrapped: _PolicyMethod[PolicyT, P, R],
    ) -> _PolicyMethod[PolicyT, P, R]:
        @functools.wraps(wrapped)
        def wrapper(self: PolicyT, *args: P.args, **kwargs: P.kwargs) -> R:
            return wrapped(self, *args, **kwargs)

        wrapper.__acl_allow__ = actions  # type: ignore[attr-defined]
        return cast(_PolicyMethod[PolicyT, P, R], wrapper)

    return decorator


def deny[PolicyT: Policy, **P, R](
    *actions: ActionSet,
) -> Callable[
    [_PolicyMethod[PolicyT, P, R]],
    _PolicyMethod[PolicyT, P, R],
]:
    if not actions:
        raise ValueError("'deny' requires at least one action")

    def decorator(
        wrapped: _PolicyMethod[PolicyT, P, R],
    ) -> _PolicyMethod[PolicyT, P, R]:
        @functools.wraps(wrapped)
        def wrapper(self: PolicyT, *args: P.args, **kwargs: P.kwargs) -> R:
            return wrapped(self, *args, **kwargs)

        wrapper.__acl_deny__ = actions  # type: ignore[attr-defined]
        return cast(_PolicyMethod[PolicyT, P, R], wrapper)

    return decorator
