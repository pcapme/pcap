CLIENT_BINARY_NAME=pcapclient
SERVER_BINARY_NAME=pcapserver

all: api test build

$(CLIENT_BINARY_NAME):
	go build -o $(CLIENT_BINARY_NAME) -v ./cmd/pcapclient

$(SERVER_BINARY_NAME):
	go build -o $(SERVER_BINARY_NAME) -v ./cmd/pcapserver

api:
	go generate ./...

build: api $(SERVER_BINARY_NAME) $(CLIENT_BINARY_NAME)

test: 
	go test -v ./...

clean: 
	go clean -x
	rm -f $(SERVER_BINARY_NAME)
	rm -f $(CLIENT_BINARY_NAME)
	rm -f api/*.pb.go

install:
	$(GOINSTALL) ./...
 
.PHONY: api build test clean install $(CLIENT_BINARY_NAME) $(SERVER_BINARY_NAME)
