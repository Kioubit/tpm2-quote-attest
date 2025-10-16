.PHONY: build clean install cli mobile-android mobile-ios

# Build the CLI binary
cli:
	go build -o bin/tpm2-quote-attest ./cmd/tpm2-quote-attest

# Build the library
build:
	go build ./...

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf mobile/build/

# Install the library
install:
	go install ./...

# Build mobile bindings for Android
mobile-android:
	mkdir mobile/build/ || true
	gomobile bind -target=android -androidapi 27 -o mobile/build/tpm2-tool-mobile.aar ./mobile

# Build mobile bindings for iOS
mobile-ios:
	gomobile bind -target=ios -o mobile/build/Tpm2ToolMobile.framework ./mobile

# Check if gomobile is installed
check-gomobile:
	@which gomobile > /dev/null || (echo "gomobile not found. Install with: go install golang.org/x/mobile/cmd/gomobile@latest" && exit 1)

# Initialize gomobile
init-mobile: check-gomobile
	gomobile init
