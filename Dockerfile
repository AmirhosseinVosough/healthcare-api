# Multi-stage: build wheels once, then a slim runtime that carries no compiler.
FROM python:3.12-slim AS build

WORKDIR /app
# Only the requirements first, so the dependency layer is cached and not
# rebuilt every time the application code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


FROM python:3.12-slim AS runtime

# A non-root user. A container that runs as root is a container whose every
# process is root the moment anything escapes the app.
RUN useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY --from=build /install /usr/local
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./
COPY scripts ./scripts
COPY docker/entrypoint.sh ./entrypoint.sh
RUN chmod +x entrypoint.sh && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

# The container answers /health, so the platform can tell running from ready.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

ENTRYPOINT ["./entrypoint.sh"]
