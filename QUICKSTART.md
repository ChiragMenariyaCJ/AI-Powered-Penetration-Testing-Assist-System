# 🐉 PTAS Quick Start - Kali Linux

## Option 1: Automated Setup (Recommended for First Run)

### One-Command Setup
```bash
# Clone the repository (if not already done)
cd /path/to/project

# Make setup script executable and run it
chmod +x kali-setup.sh
./kali-setup.sh
```

This will:
- ✅ Update system packages
- ✅ Install Python 3, pip, and venv
- ✅ Install Nmap
- ✅ Install and start MariaDB
- ✅ Create Python virtual environment
- ✅ Install all dependencies

---

## Option 2: Quick Start Script (After Initial Setup)

```bash
# From project root directory
chmod +x start.sh
./start.sh
```

This handles:
- ✅ Virtual environment activation
- ✅ Dependency installation
- ✅ Database checks
- ✅ Application startup

---

## Option 3: Manual Setup (Step-by-Step)

### 1. Install System Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap mariadb-server
```

### 2. Start Database
```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

### 3. Create Database
```bash
sudo mysql -u root <<EOF
CREATE DATABASE ptas_db;
CREATE USER 'ptas_user'@'localhost' IDENTIFIED BY 'ptas_password';
GRANT ALL PRIVILEGES ON ptas_db.* TO 'ptas_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
EOF
```

### 4. Setup Python Environment
```bash
cd /path/to/project
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r Backend/requirements.txt
```

### 5. Run Application
```bash
uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Option 4: Docker Setup (No Dependencies Needed)

### Prerequisites
```bash
# Install Docker
sudo apt install -y docker.io docker-compose

# Start Docker daemon
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (optional, to avoid sudo)
sudo usermod -aG docker $USER
newgrp docker
```

### Run with Docker Compose
```bash
cd /path/to/project
docker-compose up -d
```

Database and API will start automatically:
- **API**: http://localhost:8000
- **Database**: localhost:3306

### Stop Services
```bash
docker-compose down
```

### View Logs
```bash
docker-compose logs -f api
docker-compose logs -f db
```

---

## Verify Installation

### 1. Check API is Running
```bash
curl http://localhost:8000/
# Should return: {"message": "PTAS Backend API is running"}
```

### 2. Access API Documentation
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### 3. Check Nmap Integration
```bash
nmap -V
# Should show Nmap version
```

### 4. Check Database Connection
```bash
# From project backend directory (with venv activated)
python3
>>> from Backend.database import engine
>>> engine.connect()
>>> # Should not raise an error
```

---

## Common Commands

### Activate Virtual Environment
```bash
cd /path/to/project
source venv/bin/activate
```

### Deactivate Virtual Environment
```bash
deactivate
```

### Run in Development Mode
```bash
uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000
```

### Run in Production Mode
```bash
gunicorn -w 4 -k uvicorn.workers.UvicornWorker Backend.main:app --bind 0.0.0.0:8000
```

### View Database
```bash
mysql -u ptas_user -pptas_password ptas_db
# Show tables
MariaDB [ptas_db]> SHOW TABLES;
# Exit
MariaDB [ptas_db]> EXIT;
```

### Backup Database
```bash
mysqldump -u ptas_user -pptas_password ptas_db > backup.sql
```

### Restore Database
```bash
mysql -u ptas_user -pptas_password ptas_db < backup.sql
```

---

## Troubleshooting

### Port 8000 Already in Use
```bash
# Find process using port 8000
sudo lsof -i :8000

# Kill the process
sudo kill -9 <PID>

# Or use different port
uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8001
```

### MySQL Connection Error
```bash
# Check if MariaDB is running
sudo systemctl status mariadb

# Start if not running
sudo systemctl start mariadb

# Test connection
mysql -u ptas_user -pptas_password -h localhost
```

### Nmap Not Found Error
```bash
# Install Nmap
sudo apt install -y nmap

# Verify
which nmap
nmap -V
```

### Python Module Errors
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install --upgrade pip
pip install -r Backend/requirements.txt
```

### Permission Issues with Nmap
```bash
# Nmap may require elevated privileges for certain scans
# Run Uvicorn with sudo or configure sudo without password

# Check current user
whoami

# Add Nmap to sudoers (optional)
sudo visudo
# Add line: ptas ALL=(ALL) NOPASSWD: /usr/bin/nmap
```

---

## Testing the API

### Create a Project
```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Project",
    "description": "Testing PTAS",
    "owner_id": 1
  }'
```

### Create a Target
```bash
curl -X POST http://localhost:8000/api/targets \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 1,
    "target_value": "192.168.1.1",
    "target_type": "HOST",
    "description": "Gateway"
  }'
```

### Create a Scan
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": 1,
    "scan_name": "Initial Scan",
    "scan_type": "QUICK"
  }'
```

### Execute Scan
```bash
curl -X POST http://localhost:8000/api/scan-execution/execute/1 \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 1
  }'
```

---

## Next Steps

1. ✅ System is running
2. Create your first project
3. Add targets to scan
4. Configure scope validation
5. Execute Nmap scans
6. Review vulnerabilities
7. Generate AI recommendations
8. Export comprehensive reports

---

## Environment Variables

Copy `.env.example` to `.env` and customize:
```bash
cp .env.example .env
nano .env  # or use your favorite editor
```

Available variables:
- `DATABASE_URL` - MySQL connection string
- `API_HOST` - API listening address (default: 0.0.0.0)
- `API_PORT` - API listening port (default: 8000)
- `DEBUG` - Debug mode (True/False)
- `NMAP_TIMEOUT` - Nmap scan timeout in seconds (default: 300)

---

## Performance Tuning

### For High-Volume Scanning
```bash
# Use multiple Gunicorn workers
gunicorn -w 8 -k uvicorn.workers.UvicornWorker Backend.main:app
```

### Monitor System Resources
```bash
# Watch Nmap processes
watch -n 1 'ps aux | grep nmap'

# Monitor database
mysqltop -u ptas_user -pptas_password

# System metrics
top
htop  # if installed
```

---

## Support

For issues or questions:
1. Check logs: `tail -f /var/log/mariadb/mariadb.log`
2. Review API docs: http://localhost:8000/docs
3. Check GitHub issues (if available)
4. Ensure all prerequisites are installed
5. Verify Nmap is accessible: `which nmap`

---

**Happy Penetration Testing! 🎯**
