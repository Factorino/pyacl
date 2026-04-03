# Сравнение с Casbin

В этом документе показано, как те же политики доступа из `pyacl` выглядят при использовании [Casbin](https://casbin.org/) — одной из самых популярных библиотек авторизации для Python.

---

## Обзор различий

| Критерий | pyacl | Casbin |
|---|---|---|
| Язык политик | Чистый Python | Собственный DSL (PCONF + CSV/adapter) |
| Статический анализ | Полный (mypy/pyright) | Отсутствует |
| IDE-поддержка | Полная | Нет (строки и файлы) |
| RBAC | Да, через `RolePermissions` | Да, встроенный |
| ReBAC | Да, через методы политики | Ограниченно (через `matcher`) |
| ABAC | Да, атрибуты в методах | Да, через `matcher` |
| Тестируемость | Обычный `pytest` | Требует поднятия enforcer |
| Зависимости | Нет | `casbin`, опционально адаптеры БД |

---

## Пример 1: RBAC — роли пользователей

### pyacl

```python
@unique
class UserRole(Flag):
    USER  = auto()
    MODER = auto()
    ADMIN = auto()

class UserAction(ActionSet, entity=User):
    READ   = auto()
    CREATE = auto()
    UPDATE = auto()
    DELETE = auto()

class UserPolicy(Policy, resource=User, actions=UserAction):
    roles = RolePermissions(
        {
            UserRole.MODER: UserAction.READ | UserAction.UPDATE,
            UserRole.ADMIN: UserAction.CREATE | UserAction.DELETE,
        },
        inherit=True,
    )
```

Роли и права — это типы Python. `inherit=True` означает, что `ADMIN` получает права `MODER` автоматически.

---

### Casbin — эквивалентная конфигурация

**model.conf**
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

**policy.csv**
```csv
p, moder, user, read
p, moder, user, update
p, admin, user, create
p, admin, user, delete

g, admin, moder
```

Строка `g, admin, moder` задаёт наследование: `admin` получает права `moder`.

**Python-код**
```python
import casbin

enforcer = casbin.Enforcer("model.conf", "policy.csv")

enforcer.enforce("alice", "user", "read")   # True если alice — moder или admin
enforcer.enforce("alice", "user", "delete") # True только если alice — admin
```

---

## Пример 2: ReBAC — владелец ресурса

### pyacl

```python
class MediaPolicy(Policy, resource=Media, actions=MediaAction):
    @allow(MediaAction.UPDATE)
    def can_update(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id

    @allow(MediaAction.DELETE)
    def can_delete(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id
```

Отношение «владелец» проверяется через атрибуты объектов Python напрямую.

---

### Casbin — эквивалентная конфигурация

Casbin не имеет нативной поддержки ReBAC через атрибуты объектов. Ближайший подход — ABAC-стиль с передачей атрибутов в `enforce`:

**model.conf**
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub.id == r.obj.owner_id && r.act == p.act
```

**Python-код**
```python
# Casbin требует передавать объекты целиком или их строковые идентификаторы
# Тип r.sub и r.obj теряется — это просто Any

enforcer.enforce(subject, media_resource, "update")
```

Проблемы:
- Атрибуты `sub.id` и `obj.owner_id` нигде не объявлены — ошибки только в рантайме.
- Matcher — это строка, а не Python-код, нет IDE-поддержки.
- Невозможно проверить корректность matcher статически.

---

## Пример 3: ABAC — запрет редактирования администратора модератором

### pyacl

```python
@deny(UserAction.UPDATE)
def cannot_update_admin(self, subject: User, resource: User) -> bool:
    return subject.role == UserRole.MODER and resource.role == UserRole.ADMIN
```

`@deny` имеет приоритет над `@allow`. Логика — чистый Python с типами.

---

### Casbin — эквивалентная конфигурация

**model.conf**
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = r.sub.role == p.sub && r.act == p.act
  || (r.sub.role == "moder" && r.obj.role == "admin" && r.act == "update")
```

**policy.csv**
```csv
p, moder, user, read,   allow
p, moder, user, update, allow
p, moder, user, update, deny   # явный deny для случая admin-ресурса
p, admin, user, create, allow
p, admin, user, delete, allow
```

Проблемы:
- `deny`-правило применяется ко всем update-операциям модератора, а не только к admin-ресурсам — нужны дополнительные условия в matcher.
- Matcher разрастается и смешивает RBAC и ABAC в одну строку.
- Сложно читать и тестировать.

---

## Пример 4: Комбинированная политика (RBAC + ReBAC + ABAC)

### pyacl

```python
class MediaPolicy(Policy, resource=Media, actions=MediaAction):
    # RBAC: базовые права по роли
    roles = RolePermissions(
        {
            UserRole.USER:  MediaAction.READ | MediaAction.CREATE,
            UserRole.MODER: MediaAction.DELETE,
            UserRole.ADMIN: MediaAction.UPDATE | MediaAction.SHARE,
        },
        inherit=True,
    )

    # ReBAC: владелец может редактировать своё
    @allow(MediaAction.UPDATE)
    def can_update(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id

    # ReBAC: владелец может удалять своё
    @allow(MediaAction.DELETE)
    def can_delete(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id

    # ReBAC: владелец может шарить своё
    @allow(MediaAction.SHARE)
    def can_share(self, subject: User, resource: Media) -> bool:
        return subject.id == resource.owner_id
```

Три модели — один класс, нет переключения контекста.

---

### Casbin — эквивалентная конфигурация

**model.conf**
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.sub.role, p.sub) && r.act == p.act)
  || (r.sub.id == r.obj.owner_id && r.act == p.act)
```

**policy.csv**
```csv
# RBAC: права по ролям
p, user,  media, read
p, user,  media, create
p, moder, media, delete
p, admin, media, update
p, admin, media, share

# Наследование ролей
g, moder, user
g, admin, moder

# ReBAC: владелец (нет нативного способа — это костыль)
# Casbin не умеет "p, owner, media, update" без кастомного функтора
```

Для полноценного ReBAC потребуется кастомный функтор:

```python
def is_owner(sub, obj):
    return sub.id == obj.owner_id

enforcer.add_function("isOwner", is_owner)
```

**model.conf** с функтором:
```ini
[matchers]
m = (g(r.sub.role, p.sub) && r.act == p.act)
  || (isOwner(r.sub, r.obj) && r.act == p.act)
```

Функтор — это снова строка в конфиге и Python-функция без типов. Типы `sub` и `obj` нигде не известны.

---
