#!/bin/sh
set -ex
apk update
apk add linux-headers musl-dev gcc go libpcap-dev ca-certificates git
mkdir /go
export GOPATH=/go
go env -w GO111MODULE=on
cd /mnt
go mod tidy
env CGO_ENABLED=1 go build --ldflags "${LDFLAGS}" -o ${DIRECTORY}/gscan-${GOOS}-${GOARCH} cli/main.go
