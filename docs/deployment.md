# Deployment

## Prerequisites

ShellWatch requires:

- A `config.yaml` file (copy `config.sample.yaml` and edit to match your environment)
- An SSH key directory with private keys for your endpoints
- A persistent directory for the SQLite database

## Docker (recommended)

### Quick start

```bash
# Create directories
mkdir -p data keys

# Copy and edit config
cp config.sample.yaml config.yaml
# Edit config.yaml — set rpId, trustedWebauthnOrigins, etc.

# Generate an SSH key
ssh-keygen -t ed25519 -f ./keys/my-server.pem -C "shellwatch"

# Start
docker compose up -d
```

ShellWatch will be available at `http://localhost:3000`.

### docker run

```bash
docker run -d \
  -v ./config.yaml:/app/config.yaml:ro \
  -v ./data:/app/data \
  -v ./keys:/app/keys:ro \
  -p 3000:3000 \
  ghcr.io/rado0x54/shellwatch:latest
```

### Image tags

| Tag          | Description                                   |
| ------------ | --------------------------------------------- |
| `latest`     | Latest stable release                         |
| `X.Y.Z`      | Specific version                              |
| `X.Y`        | Latest patch for a minor version              |
| `stable`     | Tracks the `main` branch                      |
| `develop`    | Tracks the `develop` branch (may be unstable) |
| `sha-<hash>` | Specific commit build                         |

### Volumes

| Mount point        | Purpose                                              |
| ------------------ | ---------------------------------------------------- |
| `/app/config.yaml` | Configuration file (required, read-only recommended) |
| `/app/data`        | SQLite database (must be persisted)                  |
| `/app/keys`        | SSH private keys (read-only recommended)             |

### Environment variables

| Variable            | Default                       | Description                                 |
| ------------------- | ----------------------------- | ------------------------------------------- |
| `HOST`              | `0.0.0.0`                     | Bind address                                |
| `PUID`              | `1000`                        | UID the app runs as (match your host user)  |
| `PGID`              | `1000`                        | GID the app runs as (match your host group) |
| `SHELLWATCH_DB`     | `sqlite:./data/shellwatch.db` | Database connection string                  |
| `SHELLWATCH_CONFIG` | `config.yaml`                 | Config file path                            |

## Standalone tarball

For deployments without Docker.

### Install

```bash
# Download the release tarball
wget https://github.com/rado0x54/ShellWatch/releases/latest/download/shellwatch-VERSION.tar.gz
tar xzf shellwatch-*.tar.gz
cd shellwatch-*

# Install production dependencies
npm i -g pnpm
pnpm install --prod

# Configure
cp config.sample.yaml config.yaml
# Edit config.yaml

# Run
node dist/index.js
```

### Systemd service

```ini
[Unit]
Description=ShellWatch SSH session broker
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/shellwatch
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
User=shellwatch
Environment=HOST=0.0.0.0

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp shellwatch.service /etc/systemd/system/
sudo systemctl enable --now shellwatch
```

## Agent client

The ShellWatch agent client is a standalone Go binary that proxies SSH agent requests through ShellWatch. It is released separately from the main application.

Download platform-specific binaries from the [agent releases](https://github.com/rado0x54/ShellWatch/releases?q=agent) on GitHub.

Available platforms: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.

### Building from source

```bash
cd agent-client
make build                    # uses `git describe` for the version tag
make build VERSION=0.1.0      # or pin a specific version
```

The version is injected at link time via `-ldflags "-X main.Version=..."` and advertised to the server on the WebSocket handshake so it shows up on the `/sign/:id` approval page.
