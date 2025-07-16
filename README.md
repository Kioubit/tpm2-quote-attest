# TPM2 Quote Attestation Library

A Go library for verifying TPM2.0 quotes, useful for performing remote or local attestation of devices to verify system integrity.

## Features

- Verify RSA and ECDSA signatures of TPM quotes
- Validation of nonces
- Parse TPM quotes into structured data
- JSON output support
- Mobile support via Gomobile

## Installation

### Library Usage
To use as a Go library in your project:
```bash
go get github.com/Kioubit/tpm2-quote-attest
```

### CLI Installation
To install the CLI tool globally:
```bash
# Option 1: Install from source (requires Go 1.22+)
go install github.com/Kioubit/tpm2-quote-attest/cmd/tpm2-quote-attest@latest

# Option 2: Clone and build locally
git clone https://github.com/Kioubit/tpm2-quote-attest.git
cd tpm2-quote-attest
make cli
# Binary will be available at ./bin/tpm2-quote-attest
```

## Library Usage

### Basic Example

```go
package main

import (
	"fmt"
	"github.com/Kioubit/tpm2-quote-attest"
	"os"
)

func main() {
	// Load your files
	publicKey, _ := os.ReadFile("ak_public.pem")
	message, _ := os.ReadFile("quote.out")
	pcrValues, _ := os.ReadFile("quote.pcr")
	signature, _ := os.ReadFile("quote.sig")
	nonce, _ := os.ReadFile("quote.nonce")

	// Validate the quote
	result, err := tpm2quoteattest.Attest(publicKey, message, pcrValues, signature, nonce)
	if err != nil {
		panic(err)
	}

	// Use the validated data
	fmt.Printf("TPM Quote validated successfully\n")
	fmt.Printf("PCR Values: %+v\n", result.PCRValues)
}
```

### CLI Usage

```bash
# Build the CLI
make cli

# Run attestation
./bin/tpm2-quote-attest \
  -message-file data/quote.out \
  -pcr-file data/quote.pcr \
  -pubKey-file data/ak_public.pem \
  -signature-file data/quote.sig \
  -nonce-file data/quote.nonce
```

### Mobile Usage (Gomobile)

The library supports gomobile for use in mobile applications:

```bash
# Generate bindings for Android/iOS
make mobile-android
make mobile-ios
```

Then use in your mobile app:

```java
// Android example
String result = Tpm2ToolMobile.parseAndValidate(publicKey, message, pcr, signature, nonce);
```

## Generating TPM quotes

The `create-quote.sh` script shows how to create the required keys and how to perform the actual quote generation process.

## API Reference

### Functions

#### `Attest(publicKey, message, pcrValues, signature, nonce []byte) (Attested, error)`

Validates a TPM quote against provided PCR values, signature, and nonce.

**Parameters:**
- `publicKey`: PEM-encoded public key used to verify the signature
- `message`: Raw TPM quote message to validate
- `pcrValues`: PCR values in pcrs_format=values format
- `signature`: Signature to verify against the message
- `nonce`: Expected nonce value that must match the quote's extra data

**Returns:**
- `Attested`: Contains the parsed TPM data and verified PCR values
- `error`: Any validation error that occurred

### Types

#### `Attested`
```go
type Attested struct {
    TPMData   TPMSAttest
    PCRValues PCRValues
}
```

Contains the validated TPM quote data and PCR values.

## Example Output

```json
{
    "TPMData": {
        "AttestationType": "TPM_ST_ATTEST_QUOTE",
        "QualifiedSigner": {
            "Name": "AAtjsxXkcLNro2xtN3I9Cn2p0a0mXGV001zs0v4svOX7Pw=="
        },
        "ExtraData": {
            "Data": ""
        },
        "ClockInfo": {
            "Clock": 123456789,
            "ResetCount": 12,
            "RestartCount": 0,
            "Safe": true
        },
        "FirmwareVersion": 123456789012345,
        "Attested": {
            "Quote": {
                "PcrSelect": {
                    "Count": 1,
                    "PcrSelections": [
                        {
                            "HashAlgorithm": "TPM_ALG_SHA256",
                            "PcrSelect": [1, 2, 3, 4, 5, 6, 7, 8, 9]
                        }
                    ]
                },
                "PcrDigest": {
                    "Buffer": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K="
                }
            }
        }
    },
    "PCRValues": {
        "1": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "2": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "3": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "4": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "5": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "6": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "7": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "8": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "9": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K"
    }
}
