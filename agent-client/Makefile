BINARY := shellwatch-agent
CMD := ./cmd/shellwatch-agent

# Version is injected into main.Version via ldflags.
# Override at build time:  make build VERSION=0.1.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

LDFLAGS := -X main.Version=$(VERSION)

.PHONY: build clean test licenses

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	go test ./...

# Generate ../AGENT_THIRD_PARTY_LICENSES bundling every Go-module LICENSE
# referenced in go.sum. Run before publishing release binaries so attribution
# obligations from MIT/BSD-2 deps (gorilla/websocket, go-winio, etc.) ship
# alongside the artifact. Wired into .github/workflows/agent-release.yml.
licenses:
	bash scripts/bundle-licenses.sh

clean:
	rm -f $(BINARY)
