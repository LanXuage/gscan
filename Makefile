DIRECTORY=bin
LINUX_FLAGS='-linkmode external -extldflags "-static -s -w"'
WIN_FLAGS='-extldflags "-s -w"'

all: clean create-directory windows linux darwin

create-directory:
	mkdir ${DIRECTORY}

windows:
	echo "Compiling Windows binary"
	touch ${DIRECTORY}/gscan-windows-amd64.exe

darwin:
	echo "Compiling Darwin binary"
	touch ${DIRECTORY}/gscan-darwin-amd64

linux:
	echo "Compiling static Linux binary"
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=amd64 -e LDFLAGS=${LINUX_FLAGS} -iv $(PWD):/mnt amd64/alpine:3.17 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=386 -e LDFLAGS=${LINUX_FLAGS} -iv $(PWD):/mnt i386/alpine:3.17 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=arm64 -e LDFLAGS=${LINUX_FLAGS} -iv $(PWD):/mnt arm64v8/alpine:3.17 /mnt/build.sh
	
clean:
	rm -rf ${DIRECTORY}