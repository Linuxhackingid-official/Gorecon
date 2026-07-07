.PHONY: build install clean test

BINARY := gorecon
CMD_DIR := ./cmd/gorecon
INSTALL_DIR := $(HOME)/.local/bin

build:
	go build -ldflags="-s -w" -o $(BINARY) $(CMD_DIR)

install: build
	mkdir -p $(INSTALL_DIR)
	cp $(BINARY) $(INSTALL_DIR)/$(BINARY)
	@echo "Installed to $(INSTALL_DIR)/$(BINARY)"

clean:
	rm -f $(BINARY)
	go clean -cache

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

tidy:
	go mod tidy

all: fmt vet build
