# Apex Container Environment

Kali-based container to run the Apex agent with common pentest tools preinstalled (nmap, gobuster, sqlmap, etc.).

## Quick start

1. Copy `container/env.example` to `container/.env` and set your keys:
   - `ANTHROPIC_API_KEY` (required)
   - `OPENROUTER_API_KEY` (optional)
2. Build and start the container:
   ```bash
   cd container
   docker compose up --build -d
   ```
3. Exec into the container shell:
   ```bash
   docker compose exec kali-apex bash
   ```
4. Inside the container, run the agent from the mounted repo:
   ```bash
   cd ~/app
   bun install
   bun run build
   node build/index.js
   # or if installed globally inside container
   pensar
   ```

Notes:

- Use `network_mode: host` on Linux if you need full network reachability for scans.
- The image includes nmap and other common tooling for convenience.
