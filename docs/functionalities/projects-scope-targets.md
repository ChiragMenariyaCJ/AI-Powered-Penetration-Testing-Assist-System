# Projects, Scope, and Targets

A project groups one authorized assessment. Scope records describe its permitted
boundary, and targets are the specific hosts selected inside that boundary.

## Projects

Project endpoints create, list, update, and delete assessment records. The use
case verifies the owning user before creation or user-filtered listing. Project
status indicates where the assessment is in its lifecycle.

## Scope validation

Scope can represent a single IP address, CIDR network, domain, or local lab
hostname. The scope-check endpoint compares a proposed target with the stored
boundary before scanning. A successful syntax check is not permission by itself;
the student must still have explicit authorization.

## Targets

A target belongs to a project and records the host that scanning services may
receive. Target creation verifies the parent project, while scope checks prevent
an accidentally unrelated host from being treated as authorized.

## Main code

| Feature | Route | Use case | Repository |
| --- | --- | --- | --- |
| Projects | `project_routes.py` | `project_usecase.py` | `project_repository.py` |
| Scope | `scope_validation_routes.py` | `scope_validation_usecase.py` | `scope_validation_repository.py` |
| Targets | `target_routes.py` | `target_usecase.py` | `target_repository.py` |

These files live under the matching `Backend/routes`, `Backend/usecases`, and
`Backend/repositories` folders. Their models and public request/response shapes
live under `Backend/models` and `Backend/schemas`.
