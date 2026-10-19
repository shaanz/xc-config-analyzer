FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py xc_client.py security_fields.py llm_analyzer.py config_store.py exporters.py ./
COPY templates templates
COPY static static

ENV CONFIG_PATH=/app/data/config.json
# UID 999 has no /etc/passwd entry, so $HOME defaults to "/" — gunicorn's
# control-socket feature then fails trying to write /.gunicorn. Give it a
# writable HOME instead.
ENV HOME=/app
RUN mkdir -p /app/data && chown -R 999:999 /app

EXPOSE 5000

# Matches this cluster's pod security convention (runAsNonRoot, runAsUser 999).
USER 999

# Single worker: the in-memory inventory/AI-result STATE in app.py is only
# consistent with exactly one process (same pattern as the other local
# analyzer tools in this workspace).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "120", "app:app"]
