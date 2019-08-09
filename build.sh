#!/bin/bash -ex

go generate github.com/mpontillo/pcapserver
go build
