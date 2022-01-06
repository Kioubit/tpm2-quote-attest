package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

/*
tpm2-tools commands used
tpm2_createek -G rsa -c 0x810XXXXX -u ek_rsa.pub
tpm2_createak --ek-context 0x810XXXXX -G rsa -g sha256 -s rsassa --ak-context "ak.ctx" --public "ak_public.pem" --format "pem"
tpm2_quote --key-context ak.ctx --pcr-list sha256:1,2,3,4,5,6,7,8,9 --qualification quote.nonce --message "quote.out" --signature "quote.sig" --pcr "quote.pcr" --pcrs_format=values --format=plain
*/

func main() {

	if len(os.Args) != 6 {
		fmt.Printf("Usage")
		fmt.Println("For verification: <messageFile> <pcrFile> <pubKeyFile> <signatureFile> <nonceFile>")
		os.Exit(1)
	}

	// ---------------------------- Read Files --------------------------------
	messageFile, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err.Error())
	}

	// Needs to be created using  -pcrs_format=values
	pcrFile, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		log.Fatal(err.Error())
	}

	pubKeyFile, err := ioutil.ReadFile(os.Args[3])
	if err != nil {
		log.Fatal(err.Error())
	}

	signatureFile, err := ioutil.ReadFile(os.Args[4])
	if err != nil {
		log.Fatal(err.Error())
	}

	nonceFile, err := ioutil.ReadFile(os.Args[5])
	if err != nil {
		log.Fatal(err.Error())
	}
	// ------------------------------------------------------------------------

	err = VerifyRSASignature(pubKeyFile, messageFile, signatureFile)
	if err != nil {
		log.Fatal(err.Error())
	} else {
		fmt.Println("Signature verified")
	}

	result, err := MarshalRawQuoteMessage(messageFile)
	if err != nil {
		log.Fatal(err.Error())
	}

	// check nonce
	if !bytes.Equal(result.extraData.data, nonceFile) {
		fmt.Printf("OUR %x\n", nonceFile)
		fmt.Printf("%x\n", result.extraData.data)
		log.Fatal("Nonce does not match")
	}

	pcrSelection := result.attested.quote.pcrSelect.pcrSelections[0]

	if result.attested.quote.pcrSelect.count != 1 {
		log.Fatal("Selection count of 1 is supported")
	}

	q, err := ParseValuePcrFileWithList(pcrFile, GetPCRList(pcrSelection), CUSTOM_TPM_ALG{
		hashSize:  sha256.Size,
		Algorithm: TPM_ALG_SHA256,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	err = VerifyQuoteDigest(q, result.attested.quote.pcrDigest.buffer)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("Firmware Version: %x\n", result.firmwareVersion)
	fmt.Printf("Clock: %d\n", result.clockInfo.clock)
	fmt.Printf("Resetcount: %d\n", result.clockInfo.resetCount)
	fmt.Printf("Restartcount: %d\n", result.clockInfo.restartCount)
	fmt.Printf("Safe: %x\n", result.clockInfo.safe)
	fmt.Println()
	fmt.Printf("Nonce Included: %x\n", result.extraData.data)
	fmt.Printf("Digest verified: %t\n", q.DigestVerified)
	fmt.Printf("Hash algorithm used: %x\n", q.Algorithm.Algorithm)

	fmt.Printf("Quoted PCRs: %d\n", q.Selection)
	fmt.Println("PCRs:")
	for i := 0; i < len(q.Selection); i++ {
		fmt.Printf("%d -> %x\n", q.Selection[i], q.Values[q.Selection[i]])
	}

}

func VerifyRSASignature(pemPub []byte, plaintext []byte, sigRaw []byte) error {
	// PKCS1v15 with sha256

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
