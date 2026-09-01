# AI-Powered Penetration Testing Assist System

PTAS is my MSc Cyber Security project. It uses FastAPI, SQLAlchemy, MariaDB, Nmap, Ollama and Qwen 2.5 3B Instruct to scan an authorised lab target, analyse findings, suggest safe validation steps and create JSON and HTML reports.

## Start PTAS

```bash
./kali-setup.sh
./start.sh
```

In another terminal, run:

```bash
ptas
```

The API documentation is available at `http://127.0.0.1:8000/docs`.

## Main commands

```bash
ptas doctor
ptas recommend --scan-id 53
ptas report 53
```

PTAS must only be used against systems with clear permission. AI recommendations are checked against scope and safety rules, remain `PENDING_APPROVAL`, and are never executed automatically.
