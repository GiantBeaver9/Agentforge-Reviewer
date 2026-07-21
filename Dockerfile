# AgentForge — standalone adversarial-evaluation dashboard.
# Deploys as its own service (Railway/Render/Fly/any container host) and points
# at ANY OpenEMR Clinical Co-Pilot instance via environment variables.
FROM python:3.11-slim

WORKDIR /app

# Install the minimal runtime first for layer caching.
COPY requirements-deploy.txt .
RUN pip install --no-cache-dir -r requirements-deploy.txt

# App code + the data the platform reads at runtime (eval seeds, contracts).
COPY src ./src
COPY evals ./evals
COPY contracts ./contracts

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    AGENTFORGE_WEB_HOST=0.0.0.0

# Railway/Heroku inject $PORT at runtime; the app honors it (default 8800).
EXPOSE 8800

# Container healthcheck hits the unauthenticated /healthz endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8800\")}/healthz').read()" || exit 1

CMD ["python", "-m", "agentforge.web"]
