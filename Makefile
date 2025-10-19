# Build variables
APP_NAME := crowdsec-exporter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Build flags
LDFLAGS := -ldflags "-w -s -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"
BUILD_DIR := ./dist

# Default target
.PHONY: all
all: clean test build

# Build the application
.PHONY: build
build:
	@echo "Building $(APP_NAME) version $(VERSION)..."
	$(GOBUILD) $(LDFLAGS) -o $(APP_NAME) ./cmd/crowdsec-exporter

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building $(APP_NAME) for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-amd64 ./cmd/crowdsec-exporter
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-darwin-arm64 ./cmd/crowdsec-exporter
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-amd64 ./cmd/crowdsec-exporter
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-linux-arm64 ./cmd/crowdsec-exporter
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(APP_NAME)-windows-amd64.exe ./cmd/crowdsec-exporter

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(APP_NAME)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Download dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run

# Run the application
.PHONY: run
run: build
	./$(APP_NAME)

# Build Docker image
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .

# Run Docker container
.PHONY: docker-run
docker-run: docker-build
	docker run --rm $(APP_NAME):latest

# Install the application
.PHONY: install
install: build
	@echo "Installing $(APP_NAME)..."
	sudo mv $(APP_NAME) /usr/local/bin/

# Uninstall the application
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(APP_NAME)..."
	sudo rm -f /usr/local/bin/$(APP_NAME)

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Clean, test, and build"
	@echo "  build        - Build the application"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Download dependencies"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code"
	@echo "  run          - Build and run the application"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Build and run Docker container"
	@echo "  install      - Install the application system-wide"
	@echo "  uninstall    - Uninstall the application"
	@echo "  help         - Show this help message"