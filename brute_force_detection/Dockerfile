FROM python:3.11-slim-bookworm

# ── System dependencies ─────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ───────────────────────────────────────────────────
WORKDIR /app

# ── Python dependencies (cached layer) ─────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Application code ────────────────────────────────────────────────────
COPY . .

# ── Create data directories ─────────────────────────────────────────────
RUN mkdir -p data/{logs,reports,models,sample_logs}

# ── Non-root user for security ──────────────────────────────────────────
RUN useradd -m -r bruteguard \
    && chown -R bruteguard:bruteguard /app
USER bruteguard

# ── Health check ────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ── Entrypoint ──────────────────────────────────────────────────────────
EXPOSE 8000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

CMD ["python", "main.py", "--seed"]
