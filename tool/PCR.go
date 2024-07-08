package tool

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
)

type PCRValues map[int]PCRValue
type PCRValue []byte

func (v PCRValue) String() string {
	return hex.EncodeToString(v)
}
func (v PCRValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func parseValuePcrFileWithList(rawFile []byte, selectedPCRs []int, alg hash.Hash) (PCRValues, error) {
	if len(rawFile)%alg.Size() != 0 {
		return nil, errors.New("invalid PCR output or hash algorithm mismatch")
	}
	expectedPCRCount := len(rawFile) / alg.Size()
	if expectedPCRCount != len(selectedPCRs) {
		return nil, errors.New("number of PCR values in PCR output does not match the selected PCRs")
	}

	result := make(PCRValues)

	reader := bytes.NewReader(rawFile)

	for iter := 0; iter < expectedPCRCount; iter++ {
		PCRValue := make([]byte, alg.Size())
		_, err := io.ReadFull(reader, PCRValue)
		if err != nil {
			return nil, err
		}
		result[selectedPCRs[iter]] = PCRValue
	}
	return result, nil
}

func verifyQuoteDigest(quote PCRValues, selectedPCRs []int, expectedDigest []byte, alg hash.Hash) error {
	concatenated := make([]byte, 0)
	for _, selected := range selectedPCRs {
		q, ok := quote[selected]
		if !ok {
			return errors.New("invalid pcr value map")
		}
		concatenated = append(concatenated, q...)
	}

	alg.Write(concatenated)
	sum := alg.Sum(nil)

	if subtle.ConstantTimeCompare(expectedDigest, sum) == 1 {
		return nil
	} else {
		return fmt.Errorf("quote digest does not match. Expected: %X Got: %X\n", expectedDigest, sum)
	}
}

func TPMExtend(exising []byte, adding []byte, alg hash.Hash) []byte {
	concatenated := make([]byte, len(exising)+len(adding))
	concatenated = append(adding, exising...)
	alg.Write(concatenated)
	return alg.Sum(nil)
}
