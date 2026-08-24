# PTAS Complete Setup, Start, Run, and Usage Instructions

This is the operational runbook for the **AI-Powered Penetration Testing Assist System (PTAS)**. It covers first-time setup, configuration, database preparation, starting the API, using the terminal assistant, running tests, Docker, production startup, routine maintenance, and common errors.

> Use PTAS only against systems and networks that you own or have explicit written authorization to test. Define the authorized scope before scanning. PTAS recommendations are advisory and must be reviewed by the operator.

## 1. What is in this repository?

The current repository contains:

- A FastAPI backend in `Backend/`
- A MariaDB/MySQL persistence layer using SQLAlchemy
- Nmap scan execution and vulnerability parsing services
- Project, target, scope, scan, vulnerability, recommendation, and report APIs
- A two-pane native terminal workspace with a normal student shell and read-only recommendations
- Local Ollama integration for model-backed terminal advice
- Automated backend and terminal-assistant tests
- Kali setup and start scripts
- Docker and Docker Compose deployment files

There is currently no separate browser frontend in this repository. During development, use Swagger UI to interact with the API.

## 2. Important paths and commands

| Item | Location or command |
| --- | --- |
| Backend application | `Backend/main.py` |
| API import target | `Backend.main:app` |
| Development dependencies | `Backend/requirements.txt` |
| Kali dependency wrapper | `Backend/requirements-kali.txt` |
| Environment template | `.env.example` |
| Kali installer | `./kali-setup.sh` |
| API launcher | `./start.sh` |
| Terminal assistant launcher | `./ptas.sh` |
| Tests | `tests/` |
| Docker services | `docker-compose.yml` |

All commands in this guide are run from the repository root unless stated otherwise:

```bash
cd ~/Projects/AI-Powered-Penetration-Testing-Assist-System
```

## 3. Fastest first-time setup on Kali Linux

The automated installer installs Python, MariaDB, Nmap, Terminator, and Ollama;
downloads the lightweight `qwen2.5:3b-instruct` recommendation model; creates
the database and application user; creates `.venv/`; installs Python packages;
installs the global `ptas` command; and creates or updates the local `.env`.

```bash
chmod +x kali-setup.sh start.sh ptas.sh
./kali-setup.sh
```

The Ollama model download can take several minutes. Re-running setup reuses the
installed service and downloaded model layers. For a deliberately rules-only
installation, skip that step with:

```bash
PTAS_SKIP_OLLAMA=1 ./kali-setup.sh
```

To install a different model instead of the default:

```bash
PTAS_SETUP_OLLAMA_MODEL=MODEL_NAME ./kali-setup.sh
```

Review the generated `.env` before starting:

```bash
nano .env
```

Generate a persistent development JWT secret:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy that output into `SECRET_KEY=` in `.env`. Never commit `.env` or expose its passwords and secret key.

Start the backend API in the VS Code terminal and leave it running:

```bash
./start.sh
```

Then start the student terminal interface from a separate terminal:

```bash
ptas
```

The student workflow sends real HTTP requests to that API. Its route and
controller calls therefore appear in the VS Code terminal.

The default development URLs are:

- API: `http://127.0.0.1:8000`
- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- OpenAPI JSON: `http://127.0.0.1:8000/openapi.json`
- Liveness: `http://127.0.0.1:8000/health/live`
- Database readiness: `http://127.0.0.1:8000/health/ready`

Stop the development server with `Ctrl+C`.

## 4. Manual Kali/Linux setup

### 4.1 Install operating-system packages

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap mariadb-server mariadb-client
```

Verify the main tools:

```bash
python3 --version
nmap --version
mariadb --version
```

### 4.2 Start MariaDB

```bash
sudo systemctl enable --now mariadb
sudo systemctl status mariadb
```

Optional MariaDB hardening:

```bash
sudo mariadb-secure-installation
```

### 4.3 Create the local database and user

For local development, the example configuration expects database `ptas_db`, user `ptas_user`, and password `ptas_password`.

```bash
sudo mariadb
```

Run these statements inside the MariaDB prompt:

```sql
CREATE DATABASE IF NOT EXISTS ptas_db;
CREATE USER IF NOT EXISTS 'ptas_user'@'localhost' IDENTIFIED BY 'ptas_password';
GRANT ALL PRIVILEGES ON ptas_db.* TO 'ptas_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Use a strong, unique database password outside local development, and put the same value in `DATABASE_URL`.

### 4.4 Create one Python virtual environment

The project standard is a virtual environment named `.venv`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r Backend/requirements-kali.txt
```

`requirements-kali.txt` includes the shared `requirements.txt` dependencies.
Gunicorn is already listed in that shared file. Always use `python -m pip` so
packages are installed into the interpreter that will run PTAS.

Activation is optional when using `./start.sh` or `./ptas.sh`: both launchers call `.venv/bin/python` explicitly. This prevents the system Python from being selected accidentally. Activate `.venv` only when running manual Python, Pip, Uvicorn, or test commands.

To leave the environment:

```bash
deactivate
```

### 4.5 Configure environment variables

```bash
cp .env.example .env
nano .env
```

Development settings and their purpose:

| Variable | Purpose | Typical local value |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy database connection | `mysql+pymysql://ptas_user:ptas_password@localhost:3306/ptas_db` |
| `APP_ENV` | `development`, `test`, or `production` | `development` |
| `API_HOST` | Bind address used by `start.sh` | `127.0.0.1` |
| `API_PORT` | API listening port | `8000` |
| `PTAS_API_URL` | Address used by the separate `ptas` terminal client | `http://127.0.0.1:8000` |
| `DEBUG` | Development debug flag | `True` |
| `SECRET_KEY` | Signs JWT access tokens | Generate a random value |
| `ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_HOURS` | JWT lifetime | `2` |
| `NMAP_PATH` | Nmap executable | `/usr/bin/nmap` |
| `NMAP_TIMEOUT` | Scan timeout in seconds | `300` |
| `CORS_ORIGINS` | Allowed browser origins | JSON array of trusted URLs |
| `PTAS_LLM_PROVIDER` | Terminal assistant provider | `ollama` after Kali setup; `rules` in the generic template |
| `OLLAMA_BASE_URL` | Local Ollama server | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Installed recommendation model | `qwen2.5:3b-instruct` after Kali setup |

In production, `SECRET_KEY` must contain at least 32 characters. Swagger and ReDoc are disabled when `APP_ENV=production`.

## 5. Starting the backend API

### Recommended project launcher

```bash
./start.sh
```

This checks Python, Nmap, MariaDB, the configured database connection, dependencies, host, and port before launching Uvicorn. It may request `sudo` to start MariaDB.

The same terminal displays a layered trace for every API request. It shows the
request method and path, then every controller, use-case, and repository method
called before the response status and execution time. Unhandled failures
include the same context followed by a traceback.

```text
INFO: API request started | GET /api/projects/ | handler=Backend.routes.project_routes.get_all_projects
INFO: API controller calling | function=Backend.controllers.project_controller.ProjectController.get_all_projects
INFO: API usecase calling | function=Backend.usecases.project_usecase.ProjectUseCase.get_all_projects
INFO: API repository calling | function=Backend.repositories.user_repository.UserRepository.get_user_by_id
INFO: API repository returned | function=Backend.repositories.user_repository.UserRepository.get_user_by_id | duration=1.0ms
INFO: API repository calling | function=Backend.repositories.project_repository.ProjectRepository.get_projects_by_user_id
INFO: API repository returned | function=Backend.repositories.project_repository.ProjectRepository.get_projects_by_user_id | duration=2.4ms
INFO: API usecase returned | function=Backend.usecases.project_usecase.ProjectUseCase.get_all_projects | duration=3.5ms
INFO: API controller returned | function=Backend.controllers.project_controller.ProjectController.get_all_projects | duration=7.6ms
INFO: API request completed | GET /api/projects/ | handler=Backend.routes.project_routes.get_all_projects | status=200 | duration=8.1ms
```

### Direct development command

```bash
source .venv/bin/activate
python -m uvicorn Backend.main:app --reload --host 127.0.0.1 --port 8000
```

Run it from the repository root. The `:app` suffix is required: `Backend.main` is the module, and `app` is its FastAPI object.

To allow access from other machines on a trusted lab network, bind to all interfaces:

```bash
python -m uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000
```

Do not expose the development server directly to the public internet.

### Run in the background for a temporary shell session

For normal development, keep Uvicorn in its own terminal. For a durable deployment, use Docker, systemd, or another process supervisor rather than relying on shell backgrounding.

## 6. Confirming that everything works

With the API running:

```bash
curl http://127.0.0.1:8000/
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
```

Expected responses include:

```json
{"message":"PTAS Backend API is running"}
```

```json
{"status":"ok"}
```

```json
{"status":"ready"}
```

The application creates missing SQLAlchemy tables when it starts. It does not create the MariaDB database itself, so `ptas_db` must already exist.

Check Nmap availability through the API:

```bash
curl http://127.0.0.1:8000/api/scan-execution/status/nmap-availability
```

## 7. Normal API workflow

Open `http://127.0.0.1:8000/docs` and use **Try it out**. Swagger displays the current request schemas and is safer than copying stale example payloads.

A typical authorized assessment follows this order:

1. Register a user with `POST /api/auth/register`.
2. Log in with `POST /api/auth/login`.
3. Create a project with `POST /api/projects/`.
4. Add authorized scope rules with `POST /api/scope-validation/`.
5. Check a target against scope with `POST /api/scope-validation/check-target-scope`.
6. Create a target with `POST /api/targets/`.
7. Create a scan record with `POST /api/scans/`.
8. Execute it with `POST /api/scan-execution/execute/{scan_id}` and the required project identifier shown by Swagger.
9. Review results with `GET /api/scan-execution/results/{scan_id}` and the vulnerability endpoints.
10. Create and approve or reject recommendations through `/api/recommendations`.
11. Generate a report with `POST /api/reports/generate/{scan_id}`.
12. Retrieve or export the report through `/api/reports`.

Current route groups are:

- `/api/auth`
- `/api/users`
- `/api/projects`
- `/api/targets`
- `/api/scope-validation`
- `/api/scans`
- `/api/scan-execution`
- `/api/vulnerabilities`
- `/api/recommendations`
- `/api/reports`

Only create targets and execute scans within explicit authorization and the scope recorded for the project.

## 8. Terminal assistant

In Kali QTerminal, the main workflow automatically invokes **Actions → Split
View Left-Right** in the current window. Both sides are genuine terminals: the
left becomes a normal shell after setup and the right displays recommendations
only. Terminator provides the equivalent native layout when PTAS is launched
outside QTerminal. PTAS never requires tmux or executes a recommendation
automatically.

### Complete terminal-first student workflow

Keep `./start.sh` running in the VS Code terminal. To use PTAS without Swagger
or another browser interface, open a separate normal terminal and run:

```bash
ptas
```

PTAS creates two real terminals in one window without tmux. The left terminal guides the student
through registration or login, project selection, authorized scope and target
entry, and a `yes` authorization confirmation. The scope is the complete
allowed boundary (for example `192.168.56.0/24`), while the target is one host
inside it (for example `192.168.56.101`). For a single authorized host, use the
same IP for both prompts. Invalid entries are requested again. PTAS then runs
these stages:

1. A quick port and service discovery scan.
2. A detailed default-script and service-version scan.
3. An optional CVE stage using only NSE scripts tagged `vuln` and `safe`.
4. Service-aware checks using applicable installed tools such as WhatWeb,
   curl, Nikto, Gobuster, SSLScan, enum4linux-ng, and dig.
5. Finding persistence and completion checks.
6. Realtime, evidence-based validation recommendations in the right terminal.
7. A scan-specific report command and output path.

The optional stage asks for consent because the bundled Vulners script sends
detected product/version or CPE information to the external Vulners service.
PTAS records explicit NSE `VULNERABLE` results as `CONFIRMED_CVE`; version
correlations are recorded as `CVE_CANDIDATE` and require manual verification.
When a concrete product/version is available, PTAS also searches Kali's local
Exploit-DB database through `searchsploit`. Matches containing CVE identifiers
are stored as `EXPLOIT_DB_REFERENCE` findings, including multiple EDB entries
and CVEs when available. Generic service-only searches are intentionally
skipped to avoid unrelated or fabricated CVE results.

The findings are printed after each Nmap stage completes on the left. Realtime
recommendations are generated from the current evidence and persisted as report
recommendations appear on the right. When the guided workflow finishes, the
left terminal automatically becomes a normal interactive shell.

Recommendations are never executed automatically. With `--provider ollama`,
PTAS asks the local model for fresh next steps as scan evidence and terminal
output change, then filters the response before showing or saving it.

To disable the visual split and use plain output:

```bash
ptas start --plain
```

For realtime model-backed recommendations, start a local Ollama model and pass
it to PTAS:

```bash
ollama serve
ptas start --provider ollama --model YOUR_INSTALLED_MODEL
```

The completed session displays a command similar to:

```bash
./ptas.sh report --scan-id 12 --output reports/ptas-scan-12.json
```

Run the displayed command from the repository root. PTAS generates the report,
creates the `reports/` directory if necessary, and prints the absolute saved
file path.

Request refreshed realtime recommendations one at a time:

```bash
./ptas.sh recommend --scan-id 12 --provider ollama --model YOUR_INSTALLED_MODEL
```

Repeat that command for the next recommendation. PTAS records presentation
progress locally and does not execute recommendations. Restart the sequence with:

```bash
./ptas.sh recommend --scan-id 12 --provider ollama --model YOUR_INSTALLED_MODEL --reset
```

Report generation saves JSON and a styled HTML file with the same base name.
Existing JSON reports can be formatted without database access:

```bash
./ptas.sh render-report reports/ptas-scan-12.json
```

### Check prerequisites

```bash
./ptas.sh doctor
./ptas.sh --help
```

### Analyze a saved file or piped output

```bash
./ptas.sh analyze nmap-output.txt --scope 10.10.10.0/24
```

```bash
nmap -sV 10.10.10.20 | ./ptas.sh analyze - \
  --target 10.10.10.20 \
  --scope 10.10.10.0/24
```

### Follow a terminal transcript

In the assessment terminal:

```bash
script -q -f /tmp/ptas-session.log
```

In another terminal:

```bash
./ptas.sh watch --file /tmp/ptas-session.log --scope 10.10.10.0/24
```

The raw transcript is not sanitized on disk. Protect it, stop `script` with `exit`, and delete the transcript securely when it is no longer needed.

### Optional sanitized audit log

```bash
mkdir -p .ptas
./ptas.sh watch \
  --file /tmp/ptas-session.log \
  --scope 10.10.10.0/24 \
  --audit-log .ptas/session.jsonl
```

Audit logging is disabled by default. The log stores sanitized commands, findings, and suggestions rather than the complete raw transcript.

### Local Ollama advice

`./kali-setup.sh` installs Ollama, starts its system service, downloads
`qwen2.5:3b-instruct`, and writes the matching `.env` values. Verify it with:

```bash
systemctl is-active ollama
ollama list
curl http://127.0.0.1:11434/api/tags
```

For a standalone transcript watcher, the `.env` configuration is used
automatically. It can also be selected explicitly:

```bash
./ptas.sh watch \
  --file /tmp/ptas-session.log \
  --scope 10.10.10.0/24 \
  --provider ollama \
  --model qwen2.5:3b-instruct
```

PTAS refuses to send excerpts to a non-local Ollama URL unless `--allow-remote-llm` is explicitly supplied. Review authorization, privacy, and data-retention implications before allowing terminal content to leave the machine.

## 9. Restricted access-testing lab

Credential-based `ACCESS_TESTING` is restricted to a registered, host-only
Metasploitable 2 VirtualBox or VMware VM. It is disabled for ordinary PTAS targets. Follow
the complete isolation, registration, snapshot, scan, exercise, and restoration
instructions in [the restricted access-testing guide](access-testing.md).

The principal commands are:

```bash
./ptas.sh lab-register \
  --name msf2-vmnet1 \
  --provider vmware \
  --target 192.168.178.128 \
  --vm /path/to/Metasploitable2.vmx \
  --interface vmnet1 \
  --kali-source 192.168.178.129
./ptas.sh lab-check --name msf2-vmnet1
./ptas.sh access-test --scan-id 42 --lab msf2-vmnet1
```

PTAS shows one allowlisted exercise at a time and never executes it or stores a
password.

If Kali and Metasploitable are separate VMware guests and the `.vmx` file is on
the physical host, register from Kali using the target IP instead:

```bash
ping -c 1 192.168.121.130
./ptas.sh lab-register \
  --name msf2-local \
  --provider vmware-network \
  --target 192.168.121.130
./ptas.sh lab-check --name msf2-local
./ptas.sh access-test --scan-id 33 --lab msf2-local
```

## 10. Running automated tests

Activate the same environment used by the application:

```bash
source .venv/bin/activate
python -m pytest -v
```

The standard-library runner is also supported:

```bash
python -m unittest discover -v
```

Run one test module:

```bash
python -m pytest -v tests/test_terminal_assistant.py
python -m pytest -v tests/test_backend_workflows.py
```

The existing workflow tests use an in-memory SQLite database and a fake Nmap service, so they do not scan a real target.

## 11. Docker Compose setup

Docker Compose starts a MariaDB container and a production API container.

### Install and enable Docker on Kali

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
```

If your Kali repository provides the legacy package instead, install `docker-compose` and use the command supported by that package.

### Create production configuration

Back up an existing local `.env` before replacing it. Then populate the production variables manually or begin from the template:

```bash
cp .env.production.example .env
nano .env
```

Generate independent secrets:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Use separate values for `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`, and `SECRET_KEY`. Set only trusted frontend origins in `CORS_ORIGINS`.

### Build and start

```bash
sudo docker compose up --build -d
sudo docker compose ps
```

Check health and logs:

```bash
curl http://127.0.0.1:8000/health/live
curl http://127.0.0.1:8000/health/ready
sudo docker compose logs -f api
sudo docker compose logs -f db
```

The Compose API runs with `APP_ENV=production`, so `/docs` and `/redoc` are intentionally disabled.

Stop containers while preserving database data:

```bash
sudo docker compose down
```

`docker compose down -v` deletes the database volume and its data. Do not use `-v` unless permanent database deletion is intended and a backup exists.

Rebuild after dependency or Dockerfile changes:

```bash
sudo docker compose up --build -d
```

## 12. Direct production process

For a non-container production-like process, activate the environment and provide production environment variables before starting Gunicorn:

```bash
source .venv/bin/activate
APP_ENV=production \
SECRET_KEY='replace-with-a-long-random-secret' \
DATABASE_URL='mysql+pymysql://ptas_user:strong-password@localhost:3306/ptas_db' \
python -m gunicorn Backend.main:app \
  --bind 127.0.0.1:8000 \
  --workers 2 \
  --worker-class uvicorn.workers.UvicornWorker \
  --access-logfile -
```

Do not place real secrets into shell history. Prefer a protected environment file managed by systemd or a secrets manager. Put a TLS reverse proxy in front of the API and bind Gunicorn to a private interface.

## 13. Database inspection, backup, and restore

Connect to the local development database:

```bash
mariadb -u ptas_user -p ptas_db
```

Inside MariaDB:

```sql
SHOW TABLES;
SELECT DATABASE();
EXIT;
```

Create a backup without putting the password on the command line:

```bash
mariadb-dump -u ptas_user -p ptas_db > ptas_backup.sql
```

Restore after confirming the target database is correct:

```bash
mariadb -u ptas_user -p ptas_db < ptas_backup.sql
```

Treat backups as sensitive because they can contain accounts, scan targets, findings, and reports.

## 14. Updating dependencies or pulling changes

After repository changes:

```bash
git pull
source .venv/bin/activate
python -m pip install -r Backend/requirements-kali.txt
python -m pytest -v
```

Review changes before applying them in a real environment. Back up the database before migrations or major upgrades. The current application creates missing tables automatically but does not provide a migration tool for schema changes.

## 15. Troubleshooting

### `ModuleNotFoundError: No module named 'jose'`

This means Uvicorn was launched with a Python interpreter that does not contain the project dependencies. Confirm the interpreter and module:

```bash
source .venv/bin/activate
which python
python -c "import jose; print(jose.__file__)"
python -m uvicorn Backend.main:app --reload --host 127.0.0.1 --port 8000
```

If dependencies are missing:

```bash
python -m pip install -r Backend/requirements-kali.txt
```

Do not run `python -m uvicorn Backend.main` without `:app`, and do not mix `/usr/bin/python` with `.venv`.

### `No module named uvicorn` or another Python module

```bash
source .venv/bin/activate
python -m pip install -r Backend/requirements-kali.txt
python -m pip check
```

### `externally-managed-environment`

Kali protects the system Python. Do not use `sudo pip` or `--break-system-packages`; create and use `.venv` and install packages there.

### Database connection refused or access denied

```bash
sudo systemctl status mariadb
sudo systemctl start mariadb
mariadb -u ptas_user -p -h localhost ptas_db
```

Confirm that `.env` has the correct username, password, host, port, and database name. Special characters in a URL password must be URL-encoded.

### Readiness fails but liveness works

`/health/live` only confirms that the web process is running. `/health/ready` also executes `SELECT 1`; failure normally indicates a database service, credential, network, or configuration problem.

### Nmap is unavailable

```bash
sudo apt install -y nmap
which nmap
nmap --version
./ptas.sh doctor
```

Ensure `NMAP_PATH` in `.env` points to the executable returned by `which nmap`.

### Port 8000 is already in use

Inspect the owner:

```bash
sudo lsof -nP -iTCP:8000 -sTCP:LISTEN
```

Stop the known process gracefully, or use another port:

```bash
python -m uvicorn Backend.main:app --reload --host 127.0.0.1 --port 8001
```

Avoid `kill -9` unless a process cannot be stopped normally.

### `Error loading ASGI app` or `Could not import module Backend.main`

Return to the repository root and include the FastAPI object name:

```bash
cd ~/Projects/AI-Powered-Penetration-Testing-Assist-System
source .venv/bin/activate
python -m uvicorn Backend.main:app --reload
```

### `Permission denied` for a launcher

```bash
chmod +x kali-setup.sh start.sh ptas.sh
```

### Swagger `/docs` returns 404

Swagger and ReDoc are disabled in production. For local development, set this in `.env` and restart:

```dotenv
APP_ENV=development
```

Do not enable interactive API documentation on a public production deployment without considering the information exposure.

### The recommendation pane does not open

Run `./ptas.sh doctor` and confirm that QTerminal or the Terminator fallback is
available. Use `ptas --plain` when no graphical terminal session is available.

### Ollama advice does not start

```bash
sudo systemctl status ollama
sudo systemctl restart ollama
ollama list
curl http://127.0.0.1:11434/api/tags
```

If the command or service is missing, rerun `./kali-setup.sh`. Keep
`OLLAMA_BASE_URL` on localhost unless remote transfer has been deliberately
authorized.

## 16. Safe shutdown checklist

For a local development session:

1. Stop Uvicorn and the sidecar with `Ctrl+C`.
2. Exit transcript recording with `exit` if standalone `script` was used.
3. Protect or remove raw transcripts and audit logs according to the engagement rules.
4. Run `deactivate` to leave the Python environment.
5. Stop MariaDB only if other local applications do not need it: `sudo systemctl stop mariadb`.

For Docker:

```bash
sudo docker compose down
```

Database data remains in the named volume unless it is explicitly deleted.

## 17. Recommended daily development routine

```bash
cd ~/Projects/AI-Powered-Penetration-Testing-Assist-System
source .venv/bin/activate
sudo systemctl start mariadb
python -m pytest -v
./start.sh
```

In another terminal, use Swagger or analyze a recorded transcript:

```bash
cd ~/Projects/AI-Powered-Penetration-Testing-Assist-System
source .venv/bin/activate
./ptas.sh doctor
./ptas.sh watch --file /tmp/ptas-session.log --scope YOUR_AUTHORIZED_SCOPE
```

Keep `.env`, database dumps, raw terminal transcripts, audit logs, scan evidence, and generated reports out of version control unless the project explicitly provides a secure, approved storage process.
