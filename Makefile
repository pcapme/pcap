# List of expected binary names.
# (Everything in "cmd/*" should just be directory names.)
BINARIES=$(notdir $(wildcard cmd/*))
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

OS_NAME=$(shell uname -s | tr A-Z a-z)

ifeq ($(OS_NAME),linux)
    PCAPD_RUN=/run/pcapd
endif
ifeq ($(OS_NAME),darwin)
    PCAPD_RUN=/tmp/pcapd
endif
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
	sudo mkdir -p $(PCAPD_RUN)
	sudo chown $(shell id -u):$(shell id -g) $(PCAPD_RUN)
ifeq ($(OS_NAME),linux)
	    sudo setcap cap_net_raw+ep $(GOBIN)/pcapd
	    getcap $(GOBIN)/pcapd
endif
ifeq ($(OS_NAME),darwin)
	    sudo chown root $(GOBIN)/pcapd
	    sudo chmod 4775 $(GOBIN)/pcapd
endif

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
