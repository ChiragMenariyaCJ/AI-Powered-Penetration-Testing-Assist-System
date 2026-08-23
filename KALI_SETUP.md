# Kali Linux Setup Guide for PTAS

## Prerequisites Checklist

- Kali Linux (2023.x or later recommended)
- Root or sudo access
- At least 2GB free disk space
- Network connectivity

## Quick Start (Automated)

```bash
# Navigate to project root
cd /path/to/AI-Powered-Penetration-Testing-Assist-System

# Make script executable
chmod +x kali-setup.sh

# Run setup script (it requests sudo only for system operations)
./kali-setup.sh
```

## Manual Setup (Step-by-Step)

### Step 1: Update System Packages
```bash
sudo apt update
sudo apt upgrade -y
```

### Step 2: Install Python 3 and pip
```bash
sudo apt install -y python3 python3-pip python3-venv
python3 --version  # Verify installation
pip3 --version
```

### Step 3: Install Nmap
Kali Linux usually has Nmap pre-installed, but verify:
```bash
nmap --version
# If not installed:
sudo apt install -y nmap
```

### Step 4: Install Database (MariaDB/MySQL)

**Option A: MariaDB (Recommended on Kali)**
```bash
sudo apt install -y mariadb-server mariadb-client
sudo systemctl start mariadb
sudo systemctl enable mariadb
sudo mysql_secure_installation  # Optional: secure installation
```

**Option B: MySQL Community**
```bash
sudo apt install -y mysql-server mysql-client
sudo systemctl start mysql
sudo systemctl enable mysql
```

### Step 5: Create Database
```bash
# Access MySQL/MariaDB
sudo mysql -u root

# Inside MySQL shell:
CREATE DATABASE ptas_db;
CREATE USER 'ptas_user'@'localhost' IDENTIFIED BY 'ptas_password';
GRANT ALL PRIVILEGES ON ptas_db.* TO 'ptas_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 6: Clone/Navigate to Project
```bash
cd /path/to/AI-Powered-Penetration-Testing-Assist-System
```

### Step 7: Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

You should see `(venv)` prefix in your terminal.

### Step 8: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r Backend/requirements-kali.txt
```

### Step 9: Configure Database Connection
Copy the environment template and edit `.env`:

```bash
cp .env.example .env
nano .env
```

### Step 10: Run the Application

**Student terminal interface (recommended)**

The setup script installs a global launcher. First run `./start.sh` in the VS
Code terminal and leave the API running. Then open a separate normal Linux
terminal and run:

```bash
ptas
```

In Kali QTerminal this automatically performs **Actions → Split View
Left-Right** in the current window. Login/register followed by a normal command
shell stays on the left, and live recommendations stay on the right. Terminator
provides an equivalent two-terminal fallback. PTAS does not use tmux.

**Option A: Project launcher**
```bash
./start.sh
```

**Option B: Uvicorn with Auto-reload (Development)**
```bash
# From the repository root
uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000
```

**Option C: Production (Gunicorn + Uvicorn)**
```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker Backend.main:app --bind 0.0.0.0:8000
```

### Step 11: Access the Application
- **API Base URL**: `http://localhost:8000`
- **API Documentation (Swagger)**: `http://localhost:8000/docs`
- **Alternative Docs (ReDoc)**: `http://localhost:8000/redoc`

---

## Troubleshooting

### Issue: "nmap not found" error
```bash
# Verify Nmap is installed
which nmap

# If not installed:
sudo apt install -y nmap

# If issue persists, check Nmap path
nmap -h
```

### Issue: MySQL Connection Error
```bash
# Check if MySQL/MariaDB is running
sudo systemctl status mariadb
# or
sudo systemctl status mysql

# Start if not running
sudo systemctl start mariadb
```

### Issue: Port 8000 Already in Use
```bash
# Use a different port
uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8001

# Or kill the process using port 8000
sudo lsof -i :8000
sudo kill -9 <PID>
```

### Issue: Python Dependency Installation Fails
```bash
# Install system dependencies for pymysql
sudo apt install -y libmysqlclient-dev python3-dev

# Then try pip install again
pip install -r Backend/requirements-kali.txt
```

### Issue: Permission Denied on setup script
```bash
chmod +x kali-setup.sh
./kali-setup.sh
```

---

## Running Scans on Kali Linux

Since Kali is a penetration testing system, it's ideal for running this application:

1. **Local Network Scans**:
   - Use Kali's network to scan vulnerable machines
   - Example: Create a target for `192.168.1.0/24`

2. **Docker Container Targets** (if you have vulnerable containers):
   ```bash
   # Run a vulnerable service in Docker
   docker run -d --name dvwa vulnerables/web-dvwa
   
   # Add Docker container IP as target in PTAS
   ```

3. **Nmap Service Integration**:
   - Nmap is available system-wide on Kali
   - PTAS automatically uses the system Nmap installation
   - All scan types (FULL, QUICK, VULNERABILITY, PORT_SCAN) work out-of-the-box

---

## Database Persistence

To ensure your database persists between sessions:

```bash
# Check MariaDB data directory
ls -la /var/lib/mysql/ptas_db/

# Backup database
sudo mysqldump -u root ptas_db > ptas_backup.sql

# Restore from backup
sudo mysql -u root ptas_db < ptas_backup.sql
```

---

## Development Workflow on Kali

1. **Activate environment each session**:
   ```bash
   source .venv/bin/activate
   ```

2. **Start development server**:
   ```bash
   uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000
   ```

3. **In another terminal, test endpoints**:
   ```bash
   # Example: Create a project
   curl -X POST http://localhost:8000/api/projects \
     -H "Content-Type: application/json" \
     -d '{
       "project_name": "Test Project",
       "description": "Testing PTAS on Kali",
       "user_id": 1
     }'
   ```

4. **View API docs**:
   - Open browser: `http://localhost:8000/docs`
   - Test all endpoints interactively

---

## Performance Tips for Kali Linux

- **Disable live reload in production**:
  ```bash
  uvicorn Backend.main:app --host 0.0.0.0 --port 8000 --workers 4
  ```

- **Monitor Nmap resource usage**:
  ```bash
  # In another terminal
  watch -n 1 'ps aux | grep nmap'
  ```

---

## System Integration (Optional)

### Run as Systemd Service

Create `/etc/systemd/system/ptas.service`:
```ini
[Unit]
Description=PTAS API Service
After=network.target mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/AI-Powered-Penetration-Testing-Assist-System
ExecStart=/path/to/AI-Powered-Penetration-Testing-Assist-System/.venv/bin/uvicorn Backend.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ptas
sudo systemctl start ptas
sudo systemctl status ptas
```

---

## Next Steps

1. ✅ Application is running
2. Create your first project via API
3. Add targets to scan
4. Set scope validation rules
5. Execute Nmap scans
6. Review vulnerabilities
7. Generate AI recommendations
8. Export reports

---

## Support & Debugging

Enable debug logging:
```bash
# Edit Backend/main.py and add logging
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check application logs:
```bash
# If running with Uvicorn
tail -f /var/log/ptas.log
```

Check database logs:
```bash
sudo tail -f /var/log/mysql/error.log
# or for MariaDB
sudo tail -f /var/log/mariadb/mariadb.log
```
