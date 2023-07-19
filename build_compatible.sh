#!/bin/sh
set -ex
sed -i 's%^mirrorlist%#mirrorlist%g' /etc/yum.repos.d/CentOS-Base.repo
sed -i 's%#baseurl=http://mirror.centos.org/centos/$releasever%baseurl=http://vault.centos.org/6.10%g' /etc/yum.repos.d/CentOS-Base.repo
yum update -y
yum install -y gcc flex bison
curl -k -L https://go.dev/dl/go1.20.5.linux-${GOARCH}.tar.gz -o /opt/go.tar.gz
tar zxvf /opt/go.tar.gz -C /usr/local/
mkdir -p /root/go
export GOROOT=/usr/local/go
export GOPATH=/root/go
export PATH=$PATH:$GOROOT/bin
go env -w GO111MODULE=on
curl -k -L https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz -o /opt/libpcap-1.10.4.tar.gz
tar zxvf /opt/libpcap-1.10.4.tar.gz -C /opt/
cd /opt/libpcap-1.10.4/ && ./configure && make
cd /mnt && go mod tidy