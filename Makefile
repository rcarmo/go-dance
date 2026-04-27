.PHONY: test build fmt clean run

test:
	go test ./...

build:
	go build ./cmd/dance

fmt:
	gofmt -w $(shell find . -name '*.go')

clean:
	rm -rf .dance coverage.out dance

run:
	go run ./cmd/dance
