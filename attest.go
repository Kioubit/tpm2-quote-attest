package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type Attested struct {
	FirmwareVersion     uint64
	Clock               uint64
	ResetCount          uint32
	RestartCount        uint32
	Safe                []byte
	QualifiedSignerName []byte
	PCRSelection        PCRSelectionList
	PCRValues           map[int]PCRValue
	PCRHashAlgorithm    CUSTOM_TPM_ALG
}

type SignatureAlgorithm int

const (
	Signature_RSA_PKCS1v15_With_SHA256 = 0
)

func Attest(pemPublicKey []byte, messageFile []byte, pcrFile []byte, signatureFile []byte, nonceFile []byte, sigAlg SignatureAlgorithm) (Attested, error) {

	switch sigAlg {
	case Signature_RSA_PKCS1v15_With_SHA256:
		err := VerifyRSASignature(pemPublicKey, messageFile, signatureFile)
		if err != nil {
			return Attested{}, err
		}
	default:
		return Attested{}, errors.New("unsupported signing method")
	}

	result, err := MarshalRawQuoteMessage(messageFile)
	if err != nil {
		return Attested{}, err
	}

	// check nonce
	if !bytes.Equal(result.extraData.data, nonceFile) {
		return Attested{}, errors.New("nonce mismatch")
	}

	if result.attested.quote.pcrSelect.count != 1 {
		return Attested{}, errors.New("only a PCR selection count of 1 is supported")
	}

	pcrSelection := result.attested.quote.pcrSelect.pcrSelections[0]

	var pcrHashAlgorithm CUSTOM_TPM_ALG

	if bytes.Equal(pcrSelection.hashAlgorithmID, TPM_ALG_SHA256) {
		pcrHashAlgorithm = CUSTOM_TPM_ALG{
			hashSize:  sha256.Size,
			Algorithm: TPM_ALG_SHA256,
		}
	} else if bytes.Equal(pcrSelection.hashAlgorithmID, TPM_ALG_SHA1) {
		pcrHashAlgorithm = CUSTOM_TPM_ALG{
			hashSize:  sha1.Size,
			Algorithm: TPM_ALG_SHA1,
		}
	} else {
		return Attested{}, errors.New("unsupported PCR hash algorithm")
	}

	q, err := ParseValuePcrFileWithList(pcrFile, GetPCRList(pcrSelection), pcrHashAlgorithm)
	if err != nil {
		return Attested{}, err
	}

	err = VerifyQuoteDigest(q, result.attested.quote.pcrDigest.buffer)
	if err != nil {
		return Attested{}, err
	}

	if len(q.Selection) == 0 || len(q.Values) == 0 {
		return Attested{}, errors.New("empty selection")
	}

	output := Attested{
		FirmwareVersion:     result.firmwareVersion,
		Clock:               result.clockInfo.clock,
		ResetCount:          result.clockInfo.resetCount,
		RestartCount:        result.clockInfo.restartCount,
		Safe:                result.clockInfo.safe,
		QualifiedSignerName: result.qualifiedSigner.name,
		PCRSelection:        q.Selection,
		PCRValues:           q.Values,
		PCRHashAlgorithm:    pcrHashAlgorithm,
	}
	return output, nil
}

func VerifyRSASignature(pemPub []byte, plaintext []byte, sigRaw []byte) error {
	// Signature_RSA_PKCS1v15_With_SHA256

	// Decode PEM public key
	block, _ := pem.Decode([]byte(pemPub))
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	// Verify signature
	hashedPlain := sha256.Sum256([]byte(plaintext))
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashedPlain[:], sigRaw)
	if err != nil {
		return err
	}
	return nil
}
