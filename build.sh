#!/bin/sh
set -ex
# sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
apk update
apk add linux-headers musl-dev gcc go ca-certificates make flex bison
mkdir /go
export GOPATH=/go
go env -w GO111MODULE=on
wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz -O /opt/libpcap-1.10.4.tar.gz
tar zxvf /opt/libpcap-1.10.4.tar.gz -C /opt/
cd /opt/libpcap-1.10.4/ && ./configure && make
cd /mnt && go mod tidy
env CGO_ENABLED=1 CGO_LDFLAGS="-L/opt/libpcap-1.10.4" CGO_CPPFLAGS="-I/opt/libpcap-1.10.4" go build --ldflags "${LDFLAGS_A}" -o ${DIRECTORY}/gscan-${GOOS}-${GOARCH} cli/main.go
