# Verify and print TPM2.0 Quotes
Useful for performing remote or local attestation of devices to verify system integrity.
- Supports verifying RSA and ECDSA signatures of tpm quotes
- Validation of the nonce
- Outputs parsed tpm quote in JSON format
- Can be used as a library including in mobile operating systems using Gomobile

## Generating TPM quotes
The ``create-quote.sh`` script shows how to create the required keys and how to perform the actual quote generation process.

## Demo
```
user@host:~$ tpm2_quote_attest -message-file data/quote.out -pcr-file data/quote.pcr -pubKey-file data/ak_public.pem -signature-file data/quote.sig -nonce-file data/quote.nonce
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
            "Clock": 1XXXXXXX9,
            "ResetCount": 12,
            "RestartCount": 0,
            "Safe": true
        },
        "FirmwareVersion": XXXXXXXXXXXXXXX,
        "Attested": {
            "Quote": {
                "PcrSelect": {
                    "Count": 1,
                    "PcrSelections": [
                        {
                            "HashAlgorithm": "TPM_ALG_SHA256",
                            "PcrSelect": [
                                1,
                                2,
                                3,
                                4,
                                5,
                                6,
                                7,
                                8,
                                9
                            ]
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
        "0": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "1": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "2": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "3": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "4": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "5": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "6": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "7": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K",
        "8": "ZXhhbXBsZWV4YW1wbGVleGFtcGxlZXhhbXBsZWV4YW0K"
    }
}
```
