# UNVERIFIED: written without a container runtime available. Build from the repo root:
#   docker build -f deploy/Dockerfile -t yog-sidecar .
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY yog ./yog
RUN cmake -S yog -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --target yogc

FROM python:3.11-slim
RUN useradd --system --uid 10001 yog
COPY --from=build /src/build/yogc /usr/local/bin/yogc
COPY yog_platform /app/yog_platform
WORKDIR /app
USER 10001
EXPOSE 8787
# Policy bundles, public keys and the audit log are mounted; nothing is baked in.
ENTRYPOINT ["python", "-m", "yog_platform", "serve", "--yogc", "/usr/local/bin/yogc", "--host", "0.0.0.0", \
            "--bundle", "/policy/current.yogb", "--pub", "main:/keys/main.pub", "--audit", "/audit/audit.log"]
