# List of expected binary names.
# (Everything in "cmd/*" should just be directory names.)
BINARIES=$(notdir $(wildcard cmd/*))
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

PCAPD_RUN=/run/pcapd
DEFAULT_SOCKET_PATH=$(PCAPD_RUN)/socket

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
	sudo setcap cap_net_raw+ep $(GOBIN)/pcapd
	sudo mkdir -p /run/pcapd
	sudo chown $(shell id -u):$(shell id -g) /run/pcapd
	getcap $(GOBIN)/pcapd

run: install
	rm -f $(DEFAULT_SOCKET_PATH)
	$(GOBIN)/pcapd

format:
	go fmt ./...

docs:
	godoc -http=localhost:8282
 
# Useful when debugging, such as "make print-BINARIES".
print-%  : ; @echo $* = $($*)

.PHONY: api build clean docs install $(BINARIES)
