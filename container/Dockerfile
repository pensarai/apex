FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS bun

# Kali is a rolling release with no version tags, so the digest is the pin.
FROM kalilinux/kali-rolling:latest@sha256:69a9a33d98a584a537bd0f7144d20c3b6d23f3bafa9ffcf0cadf4c5f186d02ff

ENV DEBIAN_FRONTEND=noninteractive

ARG USER=pentest
ARG UID=1000
ARG GID=1000

# Core tooling and common pentest utilities
RUN apt-get update && apt-get dist-upgrade -y && \
    apt-get install -y --no-install-recommends \
      sudo git curl wget ca-certificates tmux \
      python3 python3-pip python3-venv \
      build-essential gcc g++ make cmake perl ruby \
      netcat-openbsd socat nmap tcpdump iproute2 iputils-ping \
      gdb gdb-multiarch binutils-multiarch \
      strace ltrace hexedit upx \
      binwalk radare2 \
      unzip zip xz-utils zlib1g-dev \
      gobuster sqlmap nikto hydra john hashcat \
      foremost exiftool \
      wireshark-common \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Node.js (required by @pensar/apex's pensar binary) from the official release
# tarball, checked against the SHA-256 in that release's SHASUMS256.txt. The
# version sits beside its hashes so neither changes without the other.
ARG TARGETARCH
RUN set -eu; \
    node_version=22.23.5; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
      amd64) arch=x64; sha256=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8 ;; \
      arm64) arch=arm64; sha256=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09 ;; \
      *) echo "unsupported architecture: ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/node.tar.xz \
      "https://nodejs.org/dist/v${node_version}/node-v${node_version}-linux-${arch}.tar.xz"; \
    echo "${sha256}  /tmp/node.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner; \
    rm /tmp/node.tar.xz; \
    node --version

# bun system-wide (required for @pensar/apex), the same release as console's,
# from the digest-pinned official image. BUN_INSTALL puts global installs in
# /usr/local so the non-root user can run them.
ENV BUN_INSTALL="/usr/local"
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s bun /usr/local/bin/bunx && bun --version

# Install @pensar/apex globally
ARG APEX_VERSION=2.7.0
RUN bun install -g "@pensar/apex@${APEX_VERSION}"

# Create non-root user for safety
RUN groupadd -g ${GID} ${USER} || true \
    && useradd -m -u ${UID} -g ${GID} -s /bin/bash ${USER} \
    && echo "${USER} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${USER} \
    && chmod 0440 /etc/sudoers.d/${USER}

WORKDIR /home/${USER}
USER ${USER}
ENV HOME=/home/${USER}
RUN pensar --version

# Load variables from ~/.env automatically for convenience inside the shell
# Uses set -a / source instead of xargs to handle comments and empty lines
RUN echo 'if [ -f ~/.env ]; then' >> ~/.bashrc && \
    echo '    set -a' >> ~/.bashrc && \
    echo '    source ~/.env' >> ~/.bashrc && \
    echo '    set +a' >> ~/.bashrc && \
    echo 'fi' >> ~/.bashrc && \
    echo 'if [ -f ~/.env ]; then' >> ~/.zshrc && \
    echo '    set -a' >> ~/.zshrc && \
    echo '    source ~/.env' >> ~/.zshrc && \
    echo '    set +a' >> ~/.zshrc && \
    echo 'fi' >> ~/.zshrc

# Default entrypoint: interactive shell
ENTRYPOINT ["/bin/bash"]
