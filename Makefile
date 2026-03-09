.PHONY: build check test lint sec install clean vet deps snapshot release example-scan

BINARY  := dockeraudit
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
VERSION := $(shell echo $(VERSION) | sed 's/^v//')
LDFLAGS := -ldflags "-s -w -X main.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/dockeraudit

install:
	go install $(LDFLAGS) ./cmd/dockeraudit

check: vet lint sec test

test:
	go test ./... -v -race -coverprofile=coverage.out -covermode=atomic

lint:
	golangci-lint run ./...

vet:
	go vet ./...

sec: 
	gosec ./...
	govulncheck -show verbose ./... 

clean:
	rm -rf bin/
	rm -rf dist/
	rm -rf scans/
	rm -rf coverage.out
	rm -f ./$(BINARY)

deps:
	go mod download && go mod tidy

snapshot:
	goreleaser release --snapshot --clean --skip=publish

release:
	mkdir -p bin
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64       ./cmd/dockeraudit
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-arm64       ./cmd/dockeraudit
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-amd64      ./cmd/dockeraudit
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY)-darwin-arm64      ./cmd/dockeraudit
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-windows-amd64.exe ./cmd/dockeraudit

example-scan:
	./$(BINARY) scan \
		--images alpine:latest \
		--docker ./testdata/docker/ \
		--k8s ./testdata/manifests/ \
		--tf ./testdata/terraform/ \
		--daemon \
		--format markdown