BINARY := shellwatch-agent
CMD := ./cmd/shellwatch-agent

# Version is injected into main.Version via ldflags.
# Override at build time:  make build VERSION=0.1.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

LDFLAGS := -X main.Version=$(VERSION)

.PHONY: build clean test

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

test:
	go test ./...

clean:
	rm -f $(BINARY)
