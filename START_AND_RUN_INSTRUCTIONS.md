# PTAS Complete Setup, Start, Run, and Usage Instructions

This is the operational runbook for the **AI-Powered Penetration Testing Assist System (PTAS)**. It covers first-time setup, configuration, database preparation, starting the API, using the terminal assistant, running tests, Docker, production startup, routine maintenance, and common errors.

> Use PTAS only against systems and networks that you own or have explicit written authorization to test. Define the authorized scope before scanning. PTAS recommendations are advisory and must be reviewed by the operator.

## 1. What is in this repository?

The current repository contains:

- A FastAPI backend in `Backend/`
- A MariaDB/MySQL persistence layer using SQLAlchemy
- Nmap scan execution and vulnerability parsing services
- Project, target, scope, scan, vulnerability, recommendation, and report APIs
- A read-only terminal sidecar that watches a selected tmux pane or transcript
- Optional local Ollama integration for terminal advice
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

The automated installer installs Python, MariaDB, Nmap, and tmux; creates the database and application user; creates `.venv/`; installs Python packages; and creates `.env` from the template when necessary.

```bash
chmod +x kali-setup.sh start.sh ptas.sh
./kali-setup.sh
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

Start PTAS:

```bash
./start.sh
```

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
sudo apt install -y python3 python3-pip python3-venv nmap tmux mariadb-server mariadb-client
```

Verify the main tools:

```bash
python3 --version
nmap --version
tmux -V
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

`requirements-kali.txt` includes `requirements.txt` and Gunicorn. Always use `python -m pip` so packages are installed into the interpreter that will run PTAS.

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
| `DEBUG` | Development debug flag | `True` |
| `SECRET_KEY` | Signs JWT access tokens | Generate a random value |
| `ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_HOURS` | JWT lifetime | `2` |
| `NMAP_PATH` | Nmap executable | `/usr/bin/nmap` |
| `NMAP_TIMEOUT` | Scan timeout in seconds | `300` |
| `CORS_ORIGINS` | Allowed browser origins | JSON array of trusted URLs |
| `PTAS_LLM_PROVIDER` | Terminal assistant provider | `rules` |
| `OLLAMA_BASE_URL` | Optional Ollama server | `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | Optional installed model name | Empty for rules mode |

In production, `SECRET_KEY` must contain at least 32 characters. Swagger and ReDoc are disabled when `APP_ENV=production`.

## 5. Starting the backend API

### Recommended project launcher

```bash
./start.sh
```

This checks Python, Nmap, MariaDB, the configured database connection, dependencies, host, and port before launching Uvicorn. It may request `sudo` to start MariaDB.

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

## 8. Terminal assistant (read-only sidecar)

The sidecar analyzes new output from one explicitly selected tmux pane or transcript. It sanitizes common secrets, enforces the supplied scope, and displays suggestions. It never executes suggested commands.

### Check prerequisites

```bash
./ptas.sh doctor
./ptas.sh --help
```

### Recommended two-pane tmux workflow

Start tmux:

```bash
tmux new-session -s ptas
```

Press `Ctrl+b`, then `%`, to split the terminal vertically. List pane IDs:

```bash
tmux list-panes -F '#{pane_id}  #{pane_current_command}'
```

Use one pane for the authorized assessment. If that pane is `%0`, run this in the assistant pane:

```bash
./ptas.sh watch --pane %0 --scope 10.10.10.0/24
```

Supply several authorized entries by repeating `--scope`:

```bash
./ptas.sh watch \
  --pane %0 \
  --scope 10.10.10.0/24 \
  --scope lab.example.test
```

Or create a scope file:

```text
# scope.txt
10.10.10.0/24
lab.example.test
```

Then run:

```bash
./ptas.sh watch --pane %0 --scope-file scope.txt
```

By default, existing pane content is treated as the baseline and only new output is analyzed. Use `--from-start` only when you deliberately want to analyze existing content. Stop the watcher with `Ctrl+C`.

### Analyze a saved file or piped output

```bash
./ptas.sh analyze nmap-output.txt --scope 10.10.10.0/24
```

```bash
nmap -sV 10.10.10.20 | ./ptas.sh analyze - \
  --target 10.10.10.20 \
  --scope 10.10.10.0/24
```

### Follow a terminal transcript without tmux

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
  --pane %0 \
  --scope 10.10.10.0/24 \
  --audit-log .ptas/session.jsonl
```

Audit logging is disabled by default. The log stores sanitized commands, findings, and suggestions rather than the complete raw transcript.

### Optional local Ollama advice

Rules mode requires no AI model. To use an already installed local Ollama model:

```bash
ollama serve
```

In another terminal:

```bash
ollama list
./ptas.sh watch \
  --pane %0 \
  --scope 10.10.10.0/24 \
  --provider ollama \
  --model YOUR_INSTALLED_MODEL
```

PTAS refuses to send excerpts to a non-local Ollama URL unless `--allow-remote-llm` is explicitly supplied. Review authorization, privacy, and data-retention implications before allowing terminal content to leave the machine.

## 9. Running automated tests

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

## 10. Docker Compose setup

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

## 11. Direct production process

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

## 12. Database inspection, backup, and restore

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

## 13. Updating dependencies or pulling changes

After repository changes:

```bash
git pull
source .venv/bin/activate
python -m pip install -r Backend/requirements-kali.txt
python -m pytest -v
```

Review changes before applying them in a real environment. Back up the database before migrations or major upgrades. The current application creates missing tables automatically but does not provide a migration tool for schema changes.

## 14. Troubleshooting

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

### The terminal sidecar cannot find or capture a pane

```bash
tmux list-panes -a -F '#S:#I.#{pane_index} #{pane_id}'
./ptas.sh doctor
```

Pass the exact pane ID, including `%`, and run the watcher as the same user who owns the tmux session.

### Ollama advice does not start

```bash
ollama list
curl http://127.0.0.1:11434/api/tags
```

Start `ollama serve`, choose an installed model, and keep `OLLAMA_BASE_URL` on localhost unless remote transfer has been deliberately authorized.

## 15. Safe shutdown checklist

For a local development session:

1. Stop Uvicorn and the sidecar with `Ctrl+C`.
2. Exit transcript recording with `exit` if `script` was used.
3. Protect or remove raw transcripts and audit logs according to the engagement rules.
4. Run `deactivate` to leave the Python environment.
5. Stop MariaDB only if other local applications do not need it: `sudo systemctl stop mariadb`.

For Docker:

```bash
sudo docker compose down
```

Database data remains in the named volume unless it is explicitly deleted.

## 16. Recommended daily development routine

```bash
cd ~/Projects/AI-Powered-Penetration-Testing-Assist-System
source .venv/bin/activate
sudo systemctl start mariadb
python -m pytest -v
./start.sh
```

In another terminal, use Swagger or start the scoped sidecar:

```bash
cd ~/Projects/AI-Powered-Penetration-Testing-Assist-System
source .venv/bin/activate
./ptas.sh doctor
./ptas.sh watch --pane %0 --scope YOUR_AUTHORIZED_SCOPE
```

Keep `.env`, database dumps, raw terminal transcripts, audit logs, scan evidence, and generated reports out of version control unless the project explicitly provides a secure, approved storage process.
