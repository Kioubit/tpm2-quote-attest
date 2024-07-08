package tool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
)

type Attested struct {
	TPMData   TPMSAttest
	PCRValues PCRValues
}

func Attest(pemPublicKey []byte, messageFile []byte, pcrFile []byte, signatureFile []byte, nonceFile []byte) (result Attested, err error) {
	err = verifySignature(pemPublicKey, messageFile, signatureFile)
	if err != nil {
		return
	}

	result.TPMData, err = parseRawQuoteMessage(messageFile)
	if err != nil {
		return
	}

	// check nonce
	if subtle.ConstantTimeCompare(result.TPMData.ExtraData.Data, nonceFile) == 0 {
		return Attested{}, fmt.Errorf("nonce mismatch. Got %X, wanted %X", result.TPMData.ExtraData.Data, nonceFile)
	}

	if result.TPMData.Attested.Quote.PcrSelect.Count != 1 {
		return Attested{}, errors.New("only a PCR selection count of 1 is supported")
	}

	pcrSelection := result.TPMData.Attested.Quote.PcrSelect.PcrSelections[0]

	var pcrHashAlgorithm hash.Hash
	switch pcrSelection.HashAlgorithm {
	case tpmAlgSha1:
		pcrHashAlgorithm = sha1.New()
	case tpmAlgSha256:
		pcrHashAlgorithm = sha256.New()
	case tpmAlgSha384:
		pcrHashAlgorithm = sha512.New384()
	case tpmAlgSha512:
		pcrHashAlgorithm = sha512.New()
	default:
		return Attested{}, errors.New("unsupported PCR hash algorithm")
	}

	q, err := parseValuePcrFileWithList(pcrFile, pcrHashAlgorithm)
	if err != nil {
		return
	}
	err = verifyQuoteDigest(q, result.TPMData.Attested.Quote.PcrDigest.Buffer, pcrHashAlgorithm)
	if err != nil {
		return
	}

	result.PCRValues = q
	return
}

func verifySignature(pemPub []byte, plaintext []byte, sigRaw []byte) error {
	// Decode PEM public key
	block, _ := pem.Decode(pemPub)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	hashedPlain := sha256.Sum256(plaintext)

	// Validate signature
	switch pubKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashedPlain[:], sigRaw)
		if err != nil {
			return fmt.Errorf("invalid signature: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pubKey.(*ecdsa.PublicKey), hashedPlain[:], sigRaw) {
			return errors.New("invalid signature")
		}
	default:
		return errors.New("unsupported public key algorithm")
	}
	return nil
}
