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

COPY tsconfig.json ./
COPY src/ src/
COPY client/ client/
COPY drizzle/ drizzle/

RUN pnpm build
RUN pnpm prune --prod --ignore-scripts

# Stage 3 — Runtime
FROM node:24-bookworm-slim AS runtime

RUN groupadd --system shellwatch && \
    useradd --system --gid shellwatch --no-create-home shellwatch

WORKDIR /app

COPY --from=build /app/dist/ dist/
COPY --from=build /app/node_modules/ node_modules/
COPY --from=build /app/drizzle/ drizzle/
COPY --from=build /app/package.json package.json

RUN mkdir -p /app/data /app/keys && \
    chown -R shellwatch:shellwatch /app/data /app/keys

VOLUME ["/app/data", "/app/keys"]
EXPOSE 3000

USER shellwatch

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/health').then(r=>{if(!r.ok)throw r.status}).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "dist/index.js"]
