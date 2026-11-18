BINARY  := decloak
JUDGE   := decloak-judge
PKG     := github.com/dorgrn/decloak
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build build-judge test cover lint tidy update-golden clean bench-msb

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/decloak

build-judge:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(JUDGE) ./cmd/decloak-judge

test:
	go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

update-golden:
	go test ./internal/output -update

clean:
	rm -f $(BINARY) $(JUDGE) coverage.out

# Held-out MaliciousSkillBench score (downloads the pinned dataset once; needs uv).
# Tune rules with PART=train or PART=validation, never on test.
PART ?= test
bench-msb: build
	uv run scripts/bench_msb.py --bin ./$(BINARY) --part $(PART)
