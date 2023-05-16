DIRECTORY=bin
LINUX_FLAGS='-linkmode external -extldflags "-static -s -w"'
WIN_FLAGS='-extldflags "-s -w"'
VERSION=$(subst refs/tags/,,${RELEASE_VERSION})
PLATFORM=linux

.PHONY: all create-directory init-version windows darwin linux clean wheel help


ifeq (${RELEASE_VERSION},)
VERSION=`git describe --abbrev=0 --tags`
endif

ifeq ($(shell uname),Darwin)
PLATFORM=darwin
else ifeq ($(OS),Windows_NT)
PLATFORM=windows
endif

all: clean create-directory windows linux darwin

create-directory:
	mkdir ${DIRECTORY}

init-version:
ifeq (${PLATFORM},darwin) 
	sed -i "_bak" "s/Version\s*:\s*\"[0-9\.]*\"/Version: \"${VERSION}\"/g" cmd/root.go
else 
	sed -i "s/Version\s*:\s*\"[0-9\.]*\"/Version: \"${VERSION}\"/g" cmd/root.go
endif

windows: init-version
	echo "Compiling Windows binary"
	env GOOS=windows GOARCH=amd64 go build -v -x --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-windows-amd64.exe cli/main.go
	env GOOS=windows GOARCH=386 go build -v -x --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-windows-386.exe cli/main.go

darwin: init-version
	echo "Compiling Darwin binary"
	brew install libpcap
	env CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 CGO_LDFLAGS="-L/usr/local/opt/libpcap/lib" CGO_CPPFLAGS="-I/usr/local/opt/libpcap/include" go build -v -x --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-darwin-amd64 cli/main.go
	wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz -O /usr/local/opt/libpcap-1.10.4.tar.gz
	tar zxvf /usr/local/opt/libpcap-1.10.4.tar.gz -C /usr/local/opt/
	cd /usr/local/opt/libpcap-1.10.4/ && CC=clang CFLAGS='-target arm64-apple-macos -arch arm64' ./configure --host arm64-apple-macos && make
	cd /Users/runner/work/gscan/gscan
	env CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CGO_LDFLAGS="-L/usr/local/opt/libpcap-1.10.4/" CGO_CPPFLAGS="-I/usr/local/opt/libpcap-1.10.4/" go build -v -x --ldflags ${WIN_FLAGS} -o ${DIRECTORY}/gscan-darwin-arm64 cli/main.go

linux: init-version
	echo "Compiling Linux binary"
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=amd64 -e LDFLAGS_A=${LINUX_FLAGS} -iv $(PWD):/mnt amd64/alpine:3.18 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=386 -e LDFLAGS_A=${LINUX_FLAGS} -iv $(PWD):/mnt i386/alpine:3.18 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=arm64 -e LDFLAGS_A=${LINUX_FLAGS} -iv $(PWD):/mnt arm64v8/alpine:3.18 /mnt/build.sh
	docker buildx build -t lanxuage/gscan:${VERSION} --platform "linux/386,linux/amd64,linux/arm64" --push .
	
clean:
	rm -rf ${DIRECTORY}

wheel:
	echo "Compiling wheel"
	chmod +x bin/gscan-*
	sed -i "s/__version__\s*=\s*'[0-9\.]*'/__version__ = '${VERSION}'/g" gscan/__version__.py
	pip install wheel setuptools build twine
	python -m build
	python -m twine upload -u ${PYPI_API_USERNAME} -p ${PYPI_API_TOKEN} --verbose --skip-existing dist/*

help:
	echo "help"
	echo ${VERSION}
	echo ${PLATFORM}