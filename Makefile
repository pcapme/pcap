# List of expected binary names.
# (Everything in "cmd/*" should just be directory names.)
BINARIES=$(notdir $(wildcard cmd/*))

all: test build

$(BINARIES): api
	go build -o $@ -v ./cmd/$@

api:
	go generate ./...

build: $(BINARIES)

test: api
	go test -v ./...

clean: 
	go clean -x
	rm -f $(BINARIES)
	rm -f api/*.pb.go

install: api
	go install ./...

format:
	go fmt ./...

docs:
	godoc -http=localhost:8282
 
# Useful when debugging, such as "make print-BINARIES".
print-%  : ; @echo $* = $($*)

.PHONY: api build clean docs install $(BINARIES)
