FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends     curl ca-certificates jq && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional: user can install rekor-cli later; anchor will simulate if not set.
# Example (uncomment to install a static rekor-cli binary at build time):
# RUN curl -sSLf https://github.com/sigstore/rekor/releases/latest/download/rekor-cli-linux-amd64 -o /usr/local/bin/rekor-cli \
#   && chmod +x /usr/local/bin/rekor-cli
# COPY . /app
COPY . /app
