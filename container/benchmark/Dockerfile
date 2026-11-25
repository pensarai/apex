# Docker-in-Docker image for Daytona benchmark sandboxes
# Based on official Docker DinD image for reliable nested container support
FROM docker:28.0.1-dind@sha256:71835c5efd0a0f907330f2b04b0ea8a143d0201072494e67eb7699d69281c9e2

# Install additional tools needed for benchmarks
RUN apk add --no-cache \
    bash \
    curl \
    git \
    make \
    openssl \
    jq \
    python3 \
    py3-pip \
    nodejs \
    npm

# Install docker-compose standalone (in addition to compose plugin), checked
# against the SHA-256 published with the release.
ARG COMPOSE_VERSION=2.24.5
RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) sha256=94355be1d1d395040bbda1490f98d5c7627c30798a7955e1f2a78fda33a4b3e1 ;; \
      aarch64) sha256=535e90ff9a7f24384f8a38f9f9ad49125485af7ae5ffda7226d091e5b8126948 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/docker-compose \
      "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-${arch}"; \
    echo "${sha256}  /usr/local/bin/docker-compose" | sha256sum -c -; \
    chmod +x /usr/local/bin/docker-compose

# Create working directory
WORKDIR /home/daytona

# The DinD image already has proper entrypoint for Docker daemon
# We just need to ensure it stays running