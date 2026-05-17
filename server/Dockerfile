# Multi-stage. Final image is distroless + non-root.
# Build:   docker build -t secure-llm-server:dev -f server/Dockerfile .
# Run:     docker run --rm -p 8443:8443 -v $(pwd)/data:/app/data secure-llm-server:dev

FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir uv==0.4.18
WORKDIR /src
COPY pyproject.toml uv.lock* ./
COPY protocol/ ./protocol/
COPY server/ ./server/
COPY client/ ./client/
RUN uv sync --frozen --no-dev --all-packages || uv sync --no-dev --all-packages
# Vendor the venv to /opt so the runtime stage can copy it.
RUN cp -a /src/.venv /opt/venv

FROM gcr.io/distroless/python3-debian12:nonroot
ENV PATH="/opt/venv/bin:$PATH"
COPY --from=build /opt/venv /opt/venv
COPY --from=build /src/protocol /app/protocol
COPY --from=build /src/server /app/server
COPY --from=build /src/client /app/client
WORKDIR /app
USER nonroot
EXPOSE 8443
ENV SECURE_LLM_CONFIG=/app/data/config.toml
ENTRYPOINT ["/opt/venv/bin/secure-llm-server"]
CMD ["--config", "/app/data/config.toml"]
