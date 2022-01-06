package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
)

type PCRSelectionList []int
type PCRValue []byte

type PCRQuote struct {
	Algorithm      CUSTOM_TPM_ALG
	Selection      PCRSelectionList
	Values         map[int]PCRValue
	Digest         []byte
	DigestVerified bool
}

func GetPCRList(pcrSelection TPMS_PCR_SELECTION) (list PCRSelectionList) {
	list = make([]int, 0)
	var pcrPos = 0
	var s uint8
	for s = 0; s < pcrSelection.sizeOfSelect; s++ {
		var i uint8
		for i = 0; i < 8; i++ {
			if hasBit(pcrSelection.pcrSelect[s], i) {
				list = append(list, int(i)+pcrPos)
			} else {
			}
		}
		pcrPos += 8
	}
	return
}

func hasBit(n uint8, pos uint8) bool {
	val := n & (1 << pos)
	return val > 0
}

func ParseValuePcrFileWithList(rawFile []byte, list PCRSelectionList, alg CUSTOM_TPM_ALG) (*PCRQuote, error) {
	if len(rawFile)%alg.hashSize != 0 {
		return nil, errors.New("invalid file or hash Alagorithm mismatch ")
	}
	if len(rawFile)/alg.hashSize != len(list) {
		return nil, errors.New("file does not match pcr selections in quote")
	}

	q := &PCRQuote{
		Algorithm:      alg,
		Selection:      list,
		Values:         make(map[int]PCRValue),
		DigestVerified: false,
	}

	var left = len(rawFile) / alg.hashSize
	var progress = 0
	var iter = 0
	for left > 0 {
		read := make([]byte, alg.hashSize)
		copy(read, rawFile[progress:progress+alg.hashSize])
		progress += alg.hashSize
		q.Values[list[iter]] = read
		iter++
		left--
	}

	return q, nil
}

func VerifyQuoteDigest(quote *PCRQuote, expectedDigest []byte) error {
	alg := quote.Algorithm
	tDigest := make([]byte, 0)
	for _, key := range quote.Selection {
		tDigest = append(tDigest, quote.Values[key]...)
	}

	sum := make([]byte, alg.hashSize)
	if bytes.Equal(alg.Algorithm, TPM_ALG_SHA256) {
		tsum := sha256.Sum256(tDigest)
		copy(sum, tsum[:])
	} else if bytes.Equal(alg.Algorithm, TPM_ALG_SHA1) {
		tsum := sha1.Sum(tDigest)
		copy(sum, tsum[:])
	}
	quote.Digest = sum

	if bytes.Equal(expectedDigest, sum) {
		quote.DigestVerified = true
		return nil
	} else {
		return errors.New("quote digest could not be verified")
	}
}

func TPMExtend(exising []byte, adding []byte, alg CUSTOM_TPM_ALG) (sum []byte) {
	sum = make([]byte, alg.hashSize)
	concatenated := make([]byte, len(exising)+len(adding))
	concatenated = append(adding, exising...)
	if bytes.Equal(alg.Algorithm, TPM_ALG_SHA256) {
		tsum := sha256.Sum256(concatenated)
		copy(sum, tsum[:])
	} else if bytes.Equal(alg.Algorithm, TPM_ALG_SHA1) {
		tsum := sha1.Sum(concatenated)
		copy(sum, tsum[:])
	}
	return
}
