.PHONY: build test clean install run

BINARY_NAME=terraform-lint
VERSION=1.0.0

build:
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) ./cmd/terraform-lint

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-linux-amd64 ./cmd/terraform-lint

build-darwin:
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-darwin-amd64 ./cmd/terraform-lint
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/terraform-lint

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-windows-amd64.exe ./cmd/terraform-lint

build-all: build-linux build-darwin build-windows

test:
	go test -v ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-* coverage.out
	rm -rf .tflint-backup

install: build
	mv $(BINARY_NAME) /usr/local/bin/

run: build
	./$(BINARY_NAME) scan --dir examples

deps:
	go mod download
	go mod tidy

lint:
	gofmt -l .
	go vet ./...
