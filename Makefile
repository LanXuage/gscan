DIRECTORY=bin
LINUX_FLAGS='-linkmode external -extldflags "-static -s -w"'
WIN_FLAGS='-extldflags "-s -w"'

all: clean create-directory windows linux darwin

create-directory:
	mkdir ${DIRECTORY}

windows:
	echo "Compiling Windows binary"
	env GOOS=windows GOARCH=amd64 go build --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-windwos-amd64.exe cli/main.go
	env GOOS=windows GOARCH=386 go build --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-windows-386.exe cli/main.go

darwin:
	echo "Compiling Darwin binary"
	brew install libpcap llvm
	env CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CGO_LDFLAGS="-L/usr/local/opt/libpcap/lib" CGO_CPPFLAGS="-I/usr/local/opt/libpcap/include" go build --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-darwin-amd64 cli/main.go
	wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz -O libpcap-1.10.4.tar.gz
	tar zxvf ./libpcap-1.10.4.tar.gz -C .
	cd ./libpcap-1.10.4/ && ./configure --host && make
	env CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CGO_LDFLAGS="-L/usr/local/opt/libpcap/lib" CGO_CPPFLAGS="-I/usr/local/opt/libpcap/include" go build --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-darwin-arm64 cli/main.go

linux:
	echo "Compiling static Linux binary"
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=amd64 -e LDFLAGS_A=${LINUX_FLAGS} -iv $(PWD):/mnt amd64/alpine:3.18 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=386 -e LDFLAGS_A=${LINUX_FLAGS} -iv $(PWD):/mnt i386/alpine:3.18 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=arm64 -e LDFLAGS_A=${LINUX_FLAGS} -iv $(PWD):/mnt arm64v8/alpine:3.18 /mnt/build.sh
	
clean:
	rm -rf ${DIRECTORY}