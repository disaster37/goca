GOLANGCI_LINT_VERSION := v1.61.0

.PHONY: lint test fmt vet clean

lint:
	@command -v golangci-lint >/dev/null 2>&1 || \
		{ echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."; \
		  curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_LINT_VERSION)/install.sh | \
		  sh -s -- -b $$(go env GOPATH)/bin $(GOLANGCI_LINT_VERSION); }
	golangci-lint run ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test -race -covermode=count -coverprofile=count.out -v ./...

clean:
	rm -f count.out coverage.out
