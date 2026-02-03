FROM kalilinux/kali-rolling:latest

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
      unzip zip zlib1g-dev \
      gobuster sqlmap nikto hydra john hashcat \
      foremost exiftool \
      wireshark-common \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install bun system-wide (required for @pensar/apex)
ENV BUN_INSTALL="/usr/local"
RUN curl -fsSL https://bun.sh/install | bash

# Install @pensar/apex globally
RUN bun install -g @pensar/apex

# Create non-root user for safety
RUN groupadd -g ${GID} ${USER} || true \
 && useradd -m -u ${UID} -g ${GID} -s /bin/bash ${USER} \
 && echo "${USER} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${USER} \
 && chmod 0440 /etc/sudoers.d/${USER}

WORKDIR /home/${USER}
USER ${USER}
ENV HOME=/home/${USER}

# Load variables from ~/.env automatically for convenience inside the shell
RUN echo 'if [ -f ~/.env ]; then' >> ~/.bashrc && \
    echo '    export $(cat ~/.env | xargs)' >> ~/.bashrc && \
    echo 'fi' >> ~/.bashrc && \
    echo 'if [ -f ~/.env ]; then' >> ~/.zshrc && \
    echo '    export $(cat ~/.env | xargs)' >> ~/.zshrc && \
    echo 'fi' >> ~/.zshrc


# Default entrypoint: interactive shell
ENTRYPOINT ["/bin/bash"]


