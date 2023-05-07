[English](README_EN.md)

# 介绍

`gscan`最初是为项目[gosam](https://github.com/LanXuage/gosam.git)提供基础扫描支持的。后来独立出来成为一个类似`nmap`的扫描工具，目前正在努力加强和完善中，项目很期待其他开发者的加入。也欢迎您下载[发布包](https://github.com/LanXuage/gosam/releases)来体验它，帮我们测试并反馈问题给我们。

# 特性

- [x] ~~ARP scan~~
- [ ] ICMP scan
- [x] ~~TCP port scan~~
- [x] ~~Domain support~~
- [ ] Random port support
- [ ] UDP port scan
- [ ] Service discovery
- [ ] Vulnerability discovery

# 使用

从[发布包](https://github.com/LanXuage/gosam/releases)里下载的对应系统和架构的可执行文件`gscan`。

## 查看帮助

```
$ gscan help
Gscan
   ____  ______ ____ _____    ____  
  / ___\/  ___// ___\\__  \  /    \ 
 / /_/  >___ \\  \___ / __ \|   |  \
 \___  /____  >\___  >____  /___|  /
/_____/     \/     \/     \/     \/ 
https://github.com/LanXuage/gosam/gscan

A Scanner.

Usage:
  gscan [flags]
  gscan [command]

Available Commands:
  arp         ARP Scanner
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  icmp        ICMP Scanner
  port        PORT Scanner

Flags:
  -A, --arp             with arp scan
  -D, --debug           set debug log level
  -F, --file string     file to output(unrealized)
  -H, --help            help for this command
  -I, --icmp            with icmp scan
  -O, --output string   normal, json or xml(unrealized) (default "normal")
  -T, --timeout int     global timeout(ms) (default 6500)
  -V, --version         version for gscan

Use "gscan [command] --help" for more information about a command.
```
详细命令作用参考[这里](doc/command.md)。

## 简单例子

### ARP 扫描

#### 对本地的整个局域网进行 arp 扫描

```sh
$ gscan arp -a
192.168.50.179  00:15:5d:fa:d7:e7       Microsoft Corporation
192.168.48.1    00:15:5d:ab:10:3a       Microsoft Corporation
Cost: 6.514218807s
```

#### 对指定 IP 进行 arp 扫描

```sh
$ gscan arp -h 192.168.50.179
192.168.50.179  00:15:5d:fa:d7:e7       Microsoft Corporation
Cost: 6.500702247s
```

> 注意：默认超时为6500毫秒，可以使用`-T`进行指定，单位为毫秒。

### ICMP 扫描

待补充。

### TCP Port 扫描

#### 对一个 IP 进行全端口探测

```sh
$ gscan port -h 192.168.48.1 -p 0-65535
IP                                      PORT                    TYPE    STATE
192.168.48.1                            135(epmap)              tcp     open
192.168.48.1                            5091                    tcp     open
192.168.48.1                            7680(pando-pub)         tcp     open
192.168.48.1                            5040                    tcp     open
192.168.48.1                            5357(wsdapi)            tcp     open
192.168.48.1                            2179(vmrdp)             tcp     open
192.168.48.1                            10808                   tcp     open
192.168.48.1                            10809(nbd)              tcp     open
Cost: 6.00483283s
```

#### 对一个 IP 进行全端口探测，结合 ARP 扫描结果

```sh
$ gscan port -h 192.168.48.1 -p 0-65535 -A
IP                                      MAC                     VENDOR                                          PORT                    TYPE    STATE
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           2179(vmrdp)             tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           135(epmap)              tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           5091                    tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           5357(wsdapi)            tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           5040                    tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           10809(nbd)              tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           7680(pando-pub)         tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           10808                   tcp     open
Cost: 9.013501996s
```

#### 使用全连接模式对一个 IP 进行全端口探测

```sh
$ gscan port -h 192.168.48.1 -p 0-65535 -Af
IP                                      MAC                     VENDOR                                          PORT                    TYPE    STATE
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           10808                   tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           7680(pando-pub)         tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           2179(vmrdp)             tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           5040                    tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           10809(nbd)              tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           135(epmap)              tcp     open
192.168.48.1                            00:15:5d:ab:10:3a       Microsoft Corporation                           5357(wsdapi)            tcp     open
Cost: 9.01656839s
```

> 注意：`gscan`使用的是`gopacket`模拟的全连接，所以使用`-f`参数时应该开启本地的防火墙，防止本机系统自动`rst`连接导致全连接扫描失败。

# 开发

## 从源码构建

### 环境准备

#### debain/ubuntu

```sh
apt install docker
```

#### darwin(MacOS)

```sh
brew install libpcap-dev golang git
```

### 拉取源码

```sh
git clone https://github.com/LanXuage/gscan.git
```

### 编译

```sh
make linux
```

编译完成会在项目目录下的`bin`目录生不同架构的`linux`静态可执行文件。

## 开发规范

参考[这里](doc/development.md)

# 感谢

## 开发者

- [YuSec2021](https://github.com/YuSec2021)

## 项目

- [gopacket](https://github.com/google/gopacket)
- [concurrent-map](https://github.com/orcaman/concurrent-map)
- [ants](https://github.com/panjf2000/ants)
- [cobra](https://github.com/spf13/cobra)
- [zap](https://go.uber.org/zap)
