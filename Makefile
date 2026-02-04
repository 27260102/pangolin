GOCACHE ?= /tmp/go-build
BINARY ?= pangolin

.PHONY: help tidy build run clean

help:
	@echo "Targets:"
	@echo "  tidy   - go mod tidy"
	@echo "  build  - build binary"
	@echo "  run    - build and run"
	@echo "  clean  - remove binary"

tidy:
	GOCACHE=$(GOCACHE) go mod tidy

build:
	GOCACHE=$(GOCACHE) go build -o $(BINARY)

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)
