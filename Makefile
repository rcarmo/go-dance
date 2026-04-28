.PHONY: test build fmt clean run vet list-tests fuzz check release-snapshot docker-build

test:
	go test ./...

vet:
	go vet ./...

list-tests:
	@for pkg in $$(go list ./...); do \
		echo "== $$pkg =="; \
		go test -list . $$pkg; \
	done

fuzz:
	go test -fuzz=FuzzSessionVerify -fuzztime=3s ./internal/httpserver

check: fmt vet test

build:
	go build ./cmd/dance

fmt:
	gofmt -w $(shell find . -name '*.go')

clean:
	rm -rf .dance coverage.out dance

run:
	go run ./cmd/dance

docker-build:
	docker build -t dance:dev .

release-snapshot:
	goreleaser release --snapshot --clean
