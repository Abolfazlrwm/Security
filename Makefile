.PHONY: build vet test gotest integration check clean

GO ?= go
PYTHON ?= python3

build:
	cd dirbrute && $(GO) build -o dirbrute .

vet:
	cd dirbrute && $(GO) vet ./...

test:
	$(PYTHON) -m unittest discover -s tests/unit

gotest:
	cd dirbrute && $(GO) test ./...

integration:
	$(PYTHON) tests/integration.py

check: test gotest integration

clean:
	rm -f dirbrute/dirbrute
