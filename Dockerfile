FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Nmap and the required system packages.
RUN apt-get update && apt-get install -y \
    nmap \
    gcc \
    libmysqlclient-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the Python package list.
COPY Backend/requirements.txt .

# Install the Python packages.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the application code.
COPY . .

RUN addgroup --system ptas && adduser --system --ingroup ptas ptas \
    && chown -R ptas:ptas /app

USER ptas

# Expose the API port.
EXPOSE 8000

# Check that the API is alive.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health/live', timeout=5)"

# Start the API.
CMD ["gunicorn", "Backend.main:app", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-class", "uvicorn.workers.UvicornWorker", "--access-logfile", "-"]
