# Pin a digest in your own build so the running image matches the digest you
# approve in the portal (Layer 4). `python:3.12-slim` is shown by tag for clarity;
# replace with `python:3.12-slim@sha256:...` for a reproducible, approvable image.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY astis_workload.py main.py ./

# Run as non-root; the secret only lives in this process's memory.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
USER 10001

ENTRYPOINT ["python", "main.py"]
