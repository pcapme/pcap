#!/bin/bash -ex

# go generate github.com/mpontillo/pcapserver
go generate ./...
go build ./...
go build ./cmd/pcapserver
go build ./cmd/pcapclient
