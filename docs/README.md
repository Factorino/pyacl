# pyacl

> Python-native библиотека для управления политиками доступа: RBAC, ReBAC и ABAC без кастомных DSL.

---

## Мотивация

Большинство существующих решений для управления доступом в Python требуют изучения внешнего DSL (Casbin PCONF, Cedar, OPA/Rego) или тянут за собой тяжёлые зависимости. `pyacl` предлагает другой подход: политики — это обычный Python-код, а декораторы, типы и `Flag`-перечисления из стандартной библиотеки служат единственным «языком» описания правил.

**Цели:**
- Политики читаются и тестируются как любой другой Python-код.
- Полная поддержка статического анализа (mypy, pyright) и IDE-автодополнения.
- RBAC, ReBAC и ABAC покрываются одной моделью без переключения инструментов.
- Нет YAML, нет `.conf`, нет магических строк.

---

## Ключевые концепции

### `@acl_entity` — маркировка субъектов и ресурсов

Декоратор регистрирует класс в глобальном реестре субъектов и/или ресурсов.

```python
from acl import acl_entity

@acl_entity(subject=True, resource=True)
@dataclass(kw_only=True)
class User:
    id: UserId
    username: str
    role: UserRole = UserRole.USER
```

Класс может быть одновременно субъектом (тот, кто запрашивает доступ) и ресурсом (то, к чему запрашивается доступ). Именно это позволяет описывать паттерны типа «пользователь может редактировать свой профиль».

---

### `ActionSet` — типобезопасный набор действий

`ActionSet` расширяет стандартный `Flag`, привязывая набор действий к конкретной сущности через параметр `entity`.

```python
from acl import ActionSet
from enum import auto

class MediaAction(ActionSet, entity=Media):
    READ   = auto()
    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()
    SHARE  = auto()
```

Благодаря `Flag` действия можно комбинировать через `|`:

```python
UserRole.MODER: MediaAction.READ | MediaAction.CREATE
```

---

### `RolePermissions` — RBAC с наследованием

`RolePermissions` описывает, какие действия разрешены каждой роли. Флаг `inherit=True` включает накопительное наследование: роли с большим значением `Flag` получают права всех нижестоящих ролей.

```python
from acl import RolePermissions

class MediaPolicy(Policy, resource=Media, actions=MediaAction):
    roles = RolePermissions(
        {
            UserRole.USER:  MediaAction.READ | MediaAction.CREATE,
            UserRole.MODER: MediaAction.DELETE,
            UserRole.ADMIN: MediaAction.UPDATE | MediaAction.SHARE,
        },
        inherit=True,
    )
```

При `inherit=True` и порядке ролей `USER < MODER < ADMIN`:
- `MODER` получает права `USER` + свои собственные.
- `ADMIN` получает права `USER` + `MODER` + свои собственные.

Порядок наследования выводится из значений `Flag` автоматически или задаётся явно через `role_order`.

---

### `Policy` — центральное место описания политик

`Policy` связывает ресурс, набор действий и правила доступа в единый класс. Методы политики принимают `subject` и `resource` и возвращают `bool`.

```python
from acl import Policy, allow, deny

class UserPolicy(Policy, resource=User, actions=UserAction):
    roles = RolePermissions(
        {
            UserRole.MODER: UserAction.READ | UserAction.UPDATE,
            UserRole.ADMIN: UserAction.CREATE | UserAction.DELETE,
        },
        inherit=True,
    )

    @allow(UserAction.READ)
    def can_read(self, subject: User, resource: User) -> bool:
        # ReBAC: пользователь всегда может читать свой профиль
        return subject.id == resource.id

    @allow(UserAction.UPDATE)
    def can_update(self, subject: User, resource: User) -> bool:
        return subject.id == resource.id

    @deny(UserAction.UPDATE)
    def cannot_update_admin(self, subject: User, resource: User) -> bool:
        # ABAC: модератор не может редактировать администратора
        return subject.role == UserRole.MODER and resource.role == UserRole.ADMIN

    @allow(UserAction.DELETE)
    def can_delete(self, subject: User, resource: User) -> bool:
        return subject.id == resource.id
```

---

### `@allow` и `@deny` — декларативные правила

Декораторы `@allow` и `@deny` прикрепляют к методу метаданные о том, для каких действий он определяет разрешение или запрет. Это позволяет движку проверки собирать все применимые правила автоматически.

| Декоратор | Семантика |
|-----------|-----------|
| `@allow(*actions)` | Если метод возвращает `True` — действие разрешено |
| `@deny(*actions)` | Если метод возвращает `True` — действие запрещено (приоритет над `allow`) |

`@deny` имеет приоритет над `@allow` — это позволяет добавлять точечные исключения поверх широких ролевых разрешений, не переписывая всю политику.

---

## Поддерживаемые модели контроля доступа

### RBAC (Role-Based Access Control)

Права назначаются ролям через `RolePermissions`. Роль пользователя определяет базовый набор разрешённых действий.

```python
class TagPolicy(Policy, resource=Tag, actions=TagAction):
    roles = RolePermissions(
        {
            UserRole.USER:  TagAction.READ | TagAction.CREATE,
            UserRole.MODER: TagAction.UPDATE | TagAction.DELETE,
        },
        inherit=True,
    )
```

### ReBAC (Relationship-Based Access Control)

Правила, основанные на отношениях между субъектом и ресурсом, описываются напрямую в методах политики:

```python
@allow(MediaAction.UPDATE)
def can_update(self, subject: User, resource: Media) -> bool:
    # Владелец может редактировать свои медиафайлы
    return subject.id == resource.owner_id
```

### ABAC (Attribute-Based Access Control)

Атрибуты субъекта и ресурса доступны прямо в методе:

```python
@deny(UserAction.UPDATE)
def cannot_update_admin(self, subject: User, resource: User) -> bool:
    # Атрибут role субъекта + атрибут role ресурса
    return subject.role == UserRole.MODER and resource.role == UserRole.ADMIN
```

Все три модели сочетаются в рамках одной политики без дополнительной конфигурации.

---

## Планируемые возможности

- **Движок проверки доступа** (`Enforcer`) — сбор и применение правил из `Policy`-классов.
- **Кеширование решений** — мемоизация результатов для часто проверяемых пар (subject, resource, action).
- **Аудит-лог** — трассировка того, какое правило предоставило или запретило доступ.
- **Поддержка async** — асинхронные методы политик для работы с I/O-зависимыми условиями (например, проверка через БД).
- **Иерархические ресурсы** — наследование разрешений вдоль дерева ресурсов (папки → файлы).
- **Политики с контекстом запроса** — передача IP, времени суток, device fingerprint как атрибутов среды.

---

## Сравнение с Casbin

Подробное сравнение с эквивалентными конфигурациями Casbin приведено в [CASBIN_COMPARISON.md](./CASBIN_COMPARISON.md).
