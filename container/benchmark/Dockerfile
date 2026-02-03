# Docker-in-Docker image for Daytona benchmark sandboxes
# Based on official Docker DinD image for reliable nested container support
FROM docker:28.0.1-dind

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

# Install docker-compose standalone (in addition to compose plugin)
RUN curl -SL "https://github.com/docker/compose/releases/download/v2.24.5/docker-compose-linux-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x /usr/local/bin/docker-compose

# Create working directory
WORKDIR /home/daytona

# The DinD image already has proper entrypoint for Docker daemon
# We just need to ensure it stays running