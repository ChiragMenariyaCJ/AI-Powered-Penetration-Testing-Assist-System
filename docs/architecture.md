# PTAS Architecture and Request Flow

PTAS separates HTTP handling, business decisions, and database work. This makes
each layer easier to explain and test, and prevents routes from becoming large
functions that do everything.

## API request flow

```text
Terminal / Swagger / API client
              |
              v
FastAPI route -> Controller -> Use case -> Repository -> Database
                                  |
                                  +-------> Service (Nmap, reports, AI, lab)
```

For example, login follows this path:

1. `auth_routes.login` accepts and validates the JSON request.
2. `AuthController.login` constructs the business-layer dependencies and
   delegates the operation.
3. `AuthUseCase.login` looks up the user, verifies the password, and creates the
   access token.
4. `UserRepository.get_user_by_email` performs the SQLAlchemy query.
5. The result travels back through the same layers and FastAPI serializes the
   response.

The terminal workflow uses `Backend/api_client.py`, so its operations travel
through this same path instead of calling repositories directly.

## Responsibility of each folder

### Routes

Files in `Backend/routes/` define HTTP methods and URLs. They receive validated
Pydantic request objects, acquire a database session through FastAPI dependency
injection, call a controller, and return its result. Routes should not contain
SQL queries or lengthy business rules.

### Controllers

Files in `Backend/controllers/` adapt HTTP-facing inputs to a use case. A
controller builds the repositories and services required for one feature, then
delegates work. This thin layer makes the call path explicit in both code and
debug logs.

### Use cases

Files in `Backend/usecases/` contain application rules. They verify that related
records exist, reject invalid state changes, coordinate multiple repositories or
services, and turn expected failures into useful HTTP errors.

### Repositories

Files in `Backend/repositories/` own database access. They build SQLAlchemy
queries and control commits, refreshes, and deletes. Keeping persistence here
lets use cases describe *what* must happen without embedding SQL details.

### Models and schemas

`Backend/models/` defines tables and relationships stored by SQLAlchemy.
`Backend/schemas/` defines the fields accepted from clients and returned by the
API. Models describe persistence; schemas describe the public API contract.

### Services

Files in `Backend/services/` integrate work that is not a normal database CRUD
operation: Nmap execution, service-aware tools, vulnerability parsing,
recommendation generation, HTML rendering, and isolated lab verification.

### Terminal assistant

`Backend/terminal_workflow.py` coordinates login, project selection, scope,
targets, scanning, and findings through the API. `Backend/terminal_assistant/`
analyzes sanitized output and renders guidance in the read-only pane.

## Database session lifecycle

`Backend/database.py` creates the SQLAlchemy engine and session factory. A
FastAPI dependency opens one session per request and closes it afterward.
Repositories receive that session; they do not create global connections.

## Debug tracing

`Backend/api_logging.py` adds consistent logs around four boundaries:

```text
API request -> API controller -> API usecase -> API repository
```

Each entry includes the qualified function name and duration. Request completion
also includes the status code. This is diagnostic tracing only: it does not log
passwords, tokens, or request bodies.

## Where to make a change

| Change needed | Primary location |
| --- | --- |
| Add or rename an HTTP endpoint | `Backend/routes/` |
| Change a business validation rule | `Backend/usecases/` |
| Change a query or transaction | `Backend/repositories/` |
| Change stored database fields | `Backend/models/` plus migration/schema work |
| Change request or response fields | `Backend/schemas/` |
| Change scanning or report behavior | `Backend/services/` |
| Change the guided CLI conversation | `Backend/terminal_workflow.py` |
| Change recommendation-pane analysis | `Backend/terminal_assistant/` |
