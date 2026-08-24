# PTAS — AI-Powered Penetration Testing Assist System

PTAS is a terminal-first teaching project for managing authorized security
assessments. It combines a FastAPI backend, scoped Nmap scanning, evidence-based
recommendations, vulnerability records, and report generation.

> **Academic and authorized use only.** Run PTAS only against systems you own or
> have explicit written permission to test. Recommendations are advisory and are
> never executed automatically.

## Quick start

On Kali Linux, run the setup once. It also installs the local Ollama service and
downloads the `qwen2.5:3b-instruct` recommendation model:

```bash
./kali-setup.sh
```

Start the API in the VS Code terminal:

```bash
./start.sh
```

Open a separate Linux terminal and launch the student workspace:

```bash
ptas
```

The left pane is a real interactive shell and guided workflow. The right pane is
read-only and displays live recommendations. API calls appear in the VS Code
terminal as route, controller, use-case, and repository trace messages.

Useful development addresses:

- API: `http://127.0.0.1:8000`
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- Readiness check: `http://127.0.0.1:8000/health/ready`

## Documentation

Start with the [documentation index](docs/README.md). The main guides are:

- [Complete setup, startup, and troubleshooting](docs/setup-and-running.md)
- [Terminal workspace and recommendation pane](docs/terminal-workflow.md)
- [Architecture and request flow](docs/architecture.md)
- [Feature documentation](docs/functionalities/README.md)
- [Restricted Metasploitable 2 lab](docs/access-testing.md)
- [Metasploitable setup by IP from a Kali VMware guest](docs/metasploitable/README.md)

## Project layout

```text
Backend/
├── routes/             FastAPI endpoints and request validation
├── controllers/        HTTP-to-business-layer adapters
├── usecases/           Business rules and workflow orchestration
├── repositories/       Database queries and transactions
├── models/             SQLAlchemy database tables
├── schemas/            Pydantic request and response shapes
├── services/           Nmap, reporting, recommendations, and lab services
├── terminal_assistant/ Transcript analysis and safe guidance
├── main.py             FastAPI application setup
└── terminal_workflow.py Guided terminal-first application
docs/                   Setup, architecture, and feature guides
tests/                  Automated unit and workflow tests
```

## Tests

```bash
python -m pytest -q
```

This repository is an MSc Cyber Security dissertation project by Chirag
Menariya. Its source and documentation are provided for academic assessment and
portfolio demonstration; all rights are reserved by the author.
