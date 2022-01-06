package main

import (
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

	q, err := Attest(pubKeyFile, messageFile, pcrFile, signatureFile, nonceFile, Signature_RSA_PKCS1v15_With_SHA256)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Firmware Version: %x\n", q.FirmwareVersion)
	fmt.Printf("Clock: %d\n", q.Clock)
	fmt.Printf("Resetcount: %d\n", q.ResetCount)
	fmt.Printf("Restartcount: %d\n", q.RestartCount)
	fmt.Printf("Safe: %x\n", q.Safe)
	fmt.Printf("Qualified Signer Name: %x\n", q.QualifiedSignerName)
	fmt.Println()
	fmt.Printf("Hash algorithm used: %x\n", q.PCRHashAlgorithm.Algorithm)

	fmt.Printf("Quoted PCRs: %d\n", q.PCRSelection)
	fmt.Println("PCRs:")
	for i := 0; i < len(q.PCRSelection); i++ {
		fmt.Printf("%d -> %x\n", q.PCRSelection[i], q.PCRValues[q.PCRSelection[i]])
	}

}
