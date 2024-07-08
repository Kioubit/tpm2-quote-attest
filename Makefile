BINARY=tpm2-attest
LDFLAGS=-ldflags "-s -w"
BUILDFLAGS=-trimpath

build:
	go build -o bin/${BINARY} .

release:
	CGO_ENABLED=0 GOOS=linux go build ${BUILDFLAGS} ${LDFLAGS} -o bin/${BINARY}_${VERSION}_linux_amd64.bin .

release-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ${BUILDFLAGS} ${LDFLAGS} -o bin/${BINARY}_${VERSION}_linux_amd64.bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ${BUILDFLAGS} ${LDFLAGS} -o bin/${BINARY}_${VERSION}_linux_arm64.bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm go build ${BUILDFLAGS} ${LDFLAGS} -o bin/${BINARY}_${VERSION}_linux_arm.bin

android:
	if [ ! -d "bin/" ]; then  mkdir ./bin/ ; fi
	go install golang.org/x/mobile/cmd/gomobile@latest
	gomobile bind -o bin/attest.aar -target=android -androidapi 27 ./mobile/

clean:
	if [ -d "bin/" ]; then find bin/ -type f -delete ;fi
	if [ -d "bin/" ]; then rm -d bin/ ;fi