DIRECTORY=bin
LINUX_FLAGS=-linkmode external -extldflags \"-static -s -w\"
WIN_FLAGS='-extldflags "-s -w"'
PLATFORM=linux

all: clean create-directory windows linux darwin

create-directory:
	mkdir ${DIRECTORY}

windows:
	echo "Compiling Windows binary"
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=windows -e GOARCH=amd64 -e LDFLAGS=${WIN_FLAGS} -e SUFFIX=.exe -itv $(PWD):/mnt amd64/alpine:3.17 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=windows -e GOARCH=386 -e LDFLAGS=${WIN_FLAGS} -e SUFFIX=.exe -itv $(PWD):/mnt i386/alpine:3.17 /mnt/build.sh
	# docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=windows -e GOARCH=arm64 -e LDFLAGS=${WIN_FLAGS} -e SUFFIX=.exe -itv $(PWD):/mnt arm64v8/alpine:3.17 /mnt/build.sh

darwin:
	echo "Compiling Darwin binary"
	# env CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build ${FLAGS} -o ${DIRECTORY}/${LINUX}-arm64 cli/main.go
	# env CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build ${FLAGS} -o ${DIRECTORY}/${LINUX}-amd64 cli/main.go
	# env CGO_ENABLED=1 GOOS=darwin GOARCH=386 CGO_LDFLAGS=-m32 go build ${FLAGS} -o ${DIRECTORY}/${LINUX}-386 cli/main.go

linux:
	echo "Compiling static Linux binary"
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=amd64 -e LDFLAGS="${LINUX_FLAGS}" -itv $(PWD):/mnt amd64/alpine:3.17 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=386 -e LDFLAGS="${LINUX_FLAGS}" -itv $(PWD):/mnt i386/alpine:3.17 /mnt/build.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e GOOS=linux -e GOARCH=arm64 -e LDFLAGS="${LINUX_FLAGS}" -itv $(PWD):/mnt arm64v8/alpine:3.17 /mnt/build.sh
	
clean:
	rm -rf ${DIRECTORY}

test:
	echo $(shell uname)
ifeq ($(shell uname),Darwin)
	PLATFORM=darwin
else
	ifeq ($(OS),Windows)
		PLATFORM=windows
	endif
endif
	echo ${PLATFORM}