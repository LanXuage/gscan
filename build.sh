#!/bin/sh
set -ex
sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
apk update
apk add linux-headers musl-dev gcc go libpcap-dev ca-certificates git python3
mkdir /go
export GOPATH=/go
go env -w GO111MODULE=on
go env -w GOPROXY=https://goproxy.cn,direct
cd /mnt
go mod tidy
env CGO_ENABLED=1 go build --ldflags "${LDFLAGS}" -o ${DIRECTORY}/gscan-${GOOS}-${GOARCH}${SUFFIX} cli/main.go