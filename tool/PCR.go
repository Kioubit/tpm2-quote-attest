package tool

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
)

type PCRValues map[int][]byte

func parseValuePcrFileWithList(rawFile []byte, alg hash.Hash) (PCRValues, error) {
	if len(rawFile)%alg.Size() != 0 {
		return nil, errors.New("invalid file or hash algorithm mismatch")
	}
	result := make(PCRValues)

	reader := bytes.NewReader(rawFile)

	for iter := 0; iter < len(rawFile)/alg.Size(); iter++ {
		PCRValue := make([]byte, alg.Size())
		_, err := io.ReadFull(reader, PCRValue)
		if err != nil {
			return nil, err
		}
		result[iter] = PCRValue
	}
	return result, nil
}

func verifyQuoteDigest(quote PCRValues, expectedDigest []byte, alg hash.Hash) error {
	concatenated := make([]byte, 0)
	for i := 0; i < len(quote); i++ {
		concatenated = append(concatenated, quote[i]...)
	}
	alg.Write(concatenated)
	sum := alg.Sum(nil)

	if subtle.ConstantTimeCompare(expectedDigest, sum) == 1 {
		return nil
	} else {
		fmt.Printf("%X\n\n%X\n", expectedDigest, sum)
		return errors.New("quote digest does not match")
	}
}

func TPMExtend(exising []byte, adding []byte, alg hash.Hash) []byte {
	concatenated := make([]byte, len(exising)+len(adding))
	concatenated = append(adding, exising...)
	alg.Write(concatenated)
	return alg.Sum(nil)
}
