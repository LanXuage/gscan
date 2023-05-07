DIRECTORY=bin
LINUX=gscan-linux
WIN=gscan-win
DARWIN=gscan-darwin
FLAGS=-ldflags '-s -w'
WIN-FLAGS=-ldflags -H=windowsgui

all: clean create-directory windows linux darwin

create-directory:
	mkdir ${DIRECTORY}

windows:
	echo "Compiling Windows binary"
	# env CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build ${WIN-FLAGS} -o ${DIRECTORY}/${WIN}-amd64.exe cli/main.go
	# env CGO_ENABLED=1 GOOS=windows GOARCH=arm64 go build ${WIN-FLAGS} -o ${DIRECTORY}/${WIN}-arm64.exe cli/main.go
	# env CGO_ENABLED=1 GOOS=windows GOARCH=386 CGO_LDFLAGS=-m32 go build ${WIN-FLAGS} -o ${DIRECTORY}/${WIN}-386.exe cli/main.go

darwin:
	echo "Compiling Darwin binary"
	# env CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build ${FLAGS} -o ${DIRECTORY}/${LINUX}-arm64 cli/main.go
	# env CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build ${FLAGS} -o ${DIRECTORY}/${LINUX}-amd64 cli/main.go
	# env CGO_ENABLED=1 GOOS=darwin GOARCH=386 CGO_LDFLAGS=-m32 go build ${FLAGS} -o ${DIRECTORY}/${LINUX}-386 cli/main.go

linux:
	echo "Compiling static Linux binary"
	docker run --rm -e DIRECTORY=${DIRECTORY} -e LINUX=${LINUX} -e GOARCH=amd64 -itv $(PWD):/mnt amd64/alpine:3.17 /mnt/build_linux_static.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e LINUX=${LINUX} -e GOARCH=386 -itv $(PWD):/mnt i386/alpine:3.17 /mnt/build_linux_static.sh
	docker run --rm -e DIRECTORY=${DIRECTORY} -e LINUX=${LINUX} -e GOARCH=arm64 -itv $(PWD):/mnt arm64v8/alpine:3.17 /mnt/build_linux_static.sh
	
clean:
	rm -rf ${DIRECTORY}