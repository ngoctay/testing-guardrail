# Pin to specific version with SHA256 digest for reproducible builds
# Digest from: https://hub.docker.com/_/python/tags?name=3.12.8-slim-bookworm
FROM python:3.12.8-slim-bookworm@sha256:2199a62885a12290dc9c5be3ca0681d367576ab7bf037da120e564723292a2f0

WORKDIR /app

# Install system dependencies with best practices:
# --no-install-recommends: reduces image size
# apt-get clean: removes package cache
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port (Railway uses PORT env var)
EXPOSE 8000

# Run the application using JSON notation for proper signal handling
# Uses shell form with env var expansion via /bin/sh
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
