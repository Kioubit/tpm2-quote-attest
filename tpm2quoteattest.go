// Package tpm2quoteattest provides functionality for TPM2 quote attestation validation.
// It allows verification of TPM quotes against PCR values and signatures.
package tpm2quoteattest

import "github.com/Kioubit/tpm2-quote-attest/internal/tool"

// Attested represents the result of a successful TPM quote attestation.
type Attested struct {
	TPMData   tool.TPMSAttest
	PCRValues tool.PCRValues
}

// Attest validates a TPM quote against provided PCR values, signature, and nonce.
//
// Parameters:
//   - pemPublicKey: PEM-encoded public key used to verify the signature
//   - message: Raw TPM quote message to validate
//   - pcrValues: PCR values in pcrs_format=values format
//   - signature: Signature to verify against the message
//   - nonce: Expected nonce value that must match the quote's extra data
//
// Returns:
//   - Attested: Contains the parsed TPM data and verified PCR values
//   - error: Any validation error that occurred
func Attest(pemPublicKey []byte, message []byte, pcrValues []byte, signature []byte, nonce []byte) (Attested, error) {
	result, err := tool.Attest(pemPublicKey, message, pcrValues, signature, nonce)
	if err != nil {
		return Attested{}, err
	}

	return Attested{
		TPMData:   result.TPMData,
		PCRValues: result.PCRValues,
	}, nil
}
