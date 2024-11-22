CC = go

all:
	mkdir -p build
	export CGO_ENABLED=0
	GOOS=linux GOARCH=amd64 $(CC) build -o build/spooky-amd64-linux
	GOOS=linux GOARCH=386 $(CC) build -o build/spooky-i386-linux
	GOOS=linux GOARCH=arm64 $(CC) build -o build/spooky-arm64-linux
	GOOS=linux GOARCH=arm GOARM=5 $(CC) build -o build/spooky-armv5-linux
	GOOS=linux GOARCH=arm GOARM=6 $(CC) build -o build/spooky-armv6-linux
	GOOS=linux GOARCH=arm GOARM=7 $(CC) build -o build/spooky-armv7-linux
	GOOS=darwin GOARCH=amd64 $(CC) build -o build/spooky-amd64-darwin
	GOOS=darwin GOARCH=arm64 $(CC) build -o build/spooky-arm64-darwin
	GOOS=windows GOARCH=386 $(CC) build -o build/spooky-i386-windows.exe
	GOOS=windows GOARCH=amd64 $(CC) build -o build/spooky-amd64-windows.exe

clean:
	rm -rf build
