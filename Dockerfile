# syntax=docker/dockerfile:1
# ShellWatch server image: SvelteKit client built with Node, embedded into a
# statically linked Go binary, shipped on a distroless base (no shell, no
# package manager; the binary is its own health probe via -healthcheck).

# Stage 1 — client (SvelteKit static build → web/dist) + JS license notices
FROM node:24-bookworm-slim AS client

RUN corepack enable pnpm
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY client/ client/
COPY scripts/ scripts/
RUN pnpm build:client
# Attribution for the libraries bundled into the client (xterm.js, …).
RUN node scripts/bundle-licenses.mjs

# Stage 2 — server (CGO-free Go build with the client embedded)
FROM golang:1.27-bookworm AS server

RUN apt-get update && apt-get install -y --no-install-recommends jq \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
COPY web/ web/
COPY scripts/bundle-go-licenses.sh scripts/
COPY --from=client /app/web/dist/ web/dist/
COPY --from=client /app/THIRD_PARTY_LICENSES THIRD_PARTY_LICENSES

# Build identity — supplied by CI via --build-arg. Defaults are dev fallbacks
# so a manual `docker build` without args still produces a working image.
# The tag is intentionally NOT baked here — it is stamped onto release images
# at retag time via `crane mutate --set-env GIT_TAG=...` (see release.yml) and
# read at boot by internal/buildinfo.
ARG GIT_SHA=dev
ARG GIT_REF=local
RUN printf '{"sha":"%s","ref":"%s","builtAt":"%s"}\n' \
      "${GIT_SHA:-dev}" "${GIT_REF:-local}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      > buildInfo.generated.json

RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/shellwatch ./cmd/shellwatch
# Append the Go module notices to the client half.
RUN bash scripts/bundle-go-licenses.sh
# Empty, correctly-owned mount points for the runtime stage.
RUN mkdir -p /out/data /out/keys

# Stage 3 — runtime
FROM gcr.io/distroless/static-debian12:latest AS runtime

LABEL org.opencontainers.image.source="https://github.com/rado0x54/ShellWatch"
LABEL org.opencontainers.image.description="SSH session broker with browser UI and MCP interface"
LABEL org.opencontainers.image.licenses="LicenseRef-FSL-1.1-Apache-2.0"

WORKDIR /app

# Runs as UID/GID 1000 so bind-mounted volumes owned by the typical host user
# work out of the box. Override at runtime with `--user UID:GID` / compose
# `user:` if your host uses a different UID.
COPY --from=server --chown=1000:1000 /out/shellwatch shellwatch
COPY --from=server --chown=1000:1000 /app/buildInfo.generated.json buildInfo.generated.json
COPY --from=server --chown=1000:1000 /app/THIRD_PARTY_LICENSES THIRD_PARTY_LICENSES
COPY --chown=1000:1000 LICENSE LICENSE
COPY --from=server --chown=1000:1000 /out/data data
COPY --from=server --chown=1000:1000 /out/keys keys

VOLUME ["/app/data", "/app/keys"]
EXPOSE 3000

USER 1000:1000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/shellwatch", "-healthcheck"]

CMD ["/app/shellwatch"]
