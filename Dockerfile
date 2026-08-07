# Stage 1: Builder
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN python -m venv /opt/venv && \
  /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python3.11-slim AS runtime

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin/:$PATH"

COPY app /app/app

RUN useradd -u 10001 appuser && \
  chown -R appuser:appuser /app

USER 10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import "






