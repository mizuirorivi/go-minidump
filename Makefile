NAME=minidump

.PHONY: build build32 build64 clean

ifeq ($(OS),Windows_NT)
    BUILD32 = cmd /C "set GOOS=windows&& set GOARCH=386&& go build -o build/$(NAME)_32.exe cmd/minidump/main.go"
    BUILD64 = cmd /C "set GOOS=windows&& set GOARCH=amd64&& go build -o build/$(NAME)_64.exe cmd/minidump/main.go"
    RM = powershell -Command "Remove-Item -Recurse -Force build"
else
    BUILD32 = GOOS=windows GOARCH=386 go build -o build/$(NAME)_32.exe cmd/minidump/main.go
    BUILD64 = GOOS=windows GOARCH=amd64 go build -o build/$(NAME)_64.exe cmd/minidump/main.go
    RM = rm -rf build
endif

build: build32 build64

build32:
	$(BUILD32)

build64:
	$(BUILD64)

clean:
	$(RM)