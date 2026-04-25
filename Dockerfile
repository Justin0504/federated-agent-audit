FROM python:3.11-slim AS base

WORKDIR /app

# Install only production deps first (layer caching)
COPY pyproject.toml ./
RUN pip install --no-cache-dir . 2>/dev/null || true

# Copy source
COPY src/ src/
COPY examples/ examples/

# Install the package with transport extras
RUN pip install --no-cache-dir ".[transport]"

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()" || exit 1

# Default: run the audit server
ENTRYPOINT ["federated-audit"]
CMD ["server", "--host", "0.0.0.0", "--port", "8000"]
