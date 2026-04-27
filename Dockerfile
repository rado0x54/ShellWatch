# Stage 1 — Install dependencies (including native addons)
FROM node:24-bookworm AS deps

RUN corepack enable pnpm

WORKDIR /app

# Build tools for native addons (better-sqlite3, ssh2, cbor-extract, cpu-features)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ libssl-dev \
  && rm -rf /var/lib/apt/lists/*

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Stage 2 — Build (tsc + SvelteKit static adapter)
FROM deps AS build

# Build identity — supplied by CI via --build-arg. Defaults are dev fallbacks
# so a manual `docker build` without args still produces a working image.
# Note: tag is intentionally NOT baked here — it's stamped onto release images
# at retag time via `crane mutate --set-env GIT_TAG=...` (see release.yml).
ARG GIT_SHA=dev
ARG GIT_REF=local
ARG BUILD_TIME=

COPY tsconfig.json ./
COPY src/ src/
COPY client/ client/
COPY drizzle/ drizzle/

# Bake build identity into the runtime — read by src/server/buildInfo.ts.
RUN node -e "const fs=require('fs');fs.writeFileSync('buildInfo.generated.json',JSON.stringify({sha:process.env.GIT_SHA||'dev',ref:process.env.GIT_REF||'local',builtAt:process.env.BUILD_TIME||new Date().toISOString()}));"

RUN pnpm build
RUN pnpm prune --prod --ignore-scripts

# Stage 3 — Runtime
FROM node:24-bookworm-slim AS runtime

LABEL org.opencontainers.image.source="https://github.com/rado0x54/ShellWatch"
LABEL org.opencontainers.image.description="SSH session broker with browser UI and MCP interface"

# Replace the baked-in `node` user with a named `shellwatch` user pinned to
# UID/GID 1000 so bind-mounted volumes owned by the typical host user (1000)
# work out of the box. Override at runtime with `--user UID:GID` / compose
# `user:` if your host uses a different UID.
RUN userdel node 2>/dev/null || true; \
    groupdel node 2>/dev/null || true; \
    groupadd --gid 1000 shellwatch && \
    useradd --uid 1000 --gid shellwatch --no-create-home shellwatch

WORKDIR /app

COPY --from=build --chown=shellwatch:shellwatch /app/dist/ dist/
COPY --from=build --chown=shellwatch:shellwatch /app/node_modules/ node_modules/
COPY --from=build --chown=shellwatch:shellwatch /app/drizzle/ drizzle/
COPY --from=build --chown=shellwatch:shellwatch /app/package.json package.json
COPY --from=build --chown=shellwatch:shellwatch /app/buildInfo.generated.json buildInfo.generated.json
RUN install -d -o shellwatch -g shellwatch /app/data /app/keys

VOLUME ["/app/data", "/app/keys"]
EXPOSE 3000

USER shellwatch

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/health').then(r=>{if(!r.ok)throw r.status}).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js"]
