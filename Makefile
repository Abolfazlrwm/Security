.PHONY: build vet clean

GO ?= go

build:
	cd dirbrute && $(GO) build -o dirbrute .

vet:
	cd dirbrute && $(GO) vet ./...

clean:
	rm -f dirbrute/dirbrute
