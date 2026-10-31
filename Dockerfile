FROM aquasec/trivy:0.65.0 AS trivy
FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STORAGE_PATH=/data/objects TRIVY_CACHE_DIR=/cache/trivy HOME=/home/app
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app && useradd --uid 10001 --gid app --create-home app
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
WORKDIR /app
COPY pyproject.toml README.md requirements-linux.lock.txt ./
COPY iac_guard ./iac_guard
RUN pip install --no-cache-dir -c requirements-linux.lock.txt '.[service,scanners,ui]' \
    && mkdir -p /data/objects /cache/trivy && chown -R app:app /data /cache /app
COPY --chown=app:app app.py ui.css ./
COPY --chown=app:app .streamlit ./.streamlit
COPY --chown=app:app samples ./samples
COPY --chown=app:app migrations ./migrations
COPY --chown=app:app alembic.ini ./
USER app
CMD ["uvicorn", "iac_guard.service.api:app", "--host", "0.0.0.0", "--port", "8000"]
