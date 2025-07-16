package tpm2_tool_mobile

import (
	"encoding/json"

	tpm2quoteattest "github.com/Kioubit/tpm2-quote-attest"
)

func ParseAndValidate(publicKey, message, pcr, signature, nonce []byte) (string, error) {
	result, err := tpm2quoteattest.Attest(publicKey, message, pcr, signature, nonce)
	if err != nil {
		return "", err
	}
	jBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jBytes), nil
}
