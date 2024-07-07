package tpm2_tool_mobile

import (
	"encoding/json"
	"tpm2-quote-attest/tool"
)

func ParseAndValidate(publicKey, message, pcr, signature, nonce []byte) (string, error) {
	result, err := tool.Attest(publicKey, message, pcr, signature, nonce)
	if err != nil {
		return "", err
	}
	jBytes, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(jBytes), nil
}
