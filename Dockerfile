FROM python:3.11-slim

# Install OPA binary. TARGETARCH is set by Docker buildx to amd64 or arm64 to
# match the build platform, so the right OPA static binary is pulled in either
# case. Phase 2's GHCR push pins --platform linux/amd64.
ARG OPA_VERSION=0.66.0
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -L "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_${TARGETARCH}_static" -o /usr/local/bin/opa \
    && chmod +x /usr/local/bin/opa \
    && apt-get purge -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY orchestrator/ ./orchestrator/
COPY resolver/ ./resolver/
COPY enricher/ ./enricher/
COPY pdp/ ./pdp/
COPY signer/ ./signer/
COPY fixtures/ ./fixtures/
COPY keys/ ./keys/
COPY bundle/ ./bundle/

ENV PYTHONPATH=/app
EXPOSE 8181

CMD ["uvicorn", "api.server:app", "--host", "0.0.0.0", "--port", "8181"]
