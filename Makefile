GOOS=windows
GOARCH64=amd64	
GOARCH32=386
NAME=minidump
.PHONY: build clean

build:  build32 build64

build64: 
	
	GOOS=$(GOOS) GOARCH=$(GOARCH64) go build -o build/$(NAME)_64.exe cmd/minidump/main.go
build32:
	
	GOOS=$(GOOS) GOARCH=$(GOARCH32) go build -o build/$(NAME)_32.exe cmd/minidump/main.go
clean:
	rm -rf build/*