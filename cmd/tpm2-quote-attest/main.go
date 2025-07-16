package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	tpm2quoteattest "github.com/Kioubit/tpm2-quote-attest"
)

func main() {
	var messageFilePath, pcrFilePath, pubKeyFilePath, signatureFilePath, nonceFilePath string
	var prettyPrint bool
	flag.StringVar(&messageFilePath, "message-file", "", "Path to message file")
	flag.StringVar(&pcrFilePath, "pcr-file", "", "Path to pcr file (in pcrs_format=values)")
	flag.StringVar(&pubKeyFilePath, "pubKey-file", "", "Path to public key file (in PEM format)")
	flag.StringVar(&signatureFilePath, "signature-file", "", "Path to signature file")
	flag.StringVar(&nonceFilePath, "nonce-file", "", "Path to nonce file")
	flag.BoolVar(&prettyPrint, "pretty", true, "Pretty-print JSON output (optional)")
	flag.Parse()

	if flag.NFlag() < 5 {
		flag.Usage()
		os.Exit(1)
	}

	var err error

	// ---------------------------- Read Files --------------------------------
	messageFile, err := os.ReadFile(messageFilePath)
	if err != nil {
		fmt.Println("Error reading message file:", err)
		os.Exit(1)
	}

	pcrFile, err := os.ReadFile(pcrFilePath)
	if err != nil {
		fmt.Println("Error reading pcr file:", err)
		os.Exit(1)
	}

	pubKeyFile, err := os.ReadFile(pubKeyFilePath)
	if err != nil {
		fmt.Println("Error reading public key file:", err)
		os.Exit(1)
	}

	signatureFile, err := os.ReadFile(signatureFilePath)
	if err != nil {
		fmt.Println("Error reading signature file:", err)
		os.Exit(1)
	}

	nonceFile, err := os.ReadFile(nonceFilePath)
	if err != nil {
		fmt.Println("Error reading nonce file:", err)
		os.Exit(1)
	}
	// ------------------------------------------------------------------------

	q, err := tpm2quoteattest.Attest(pubKeyFile, messageFile, pcrFile, signatureFile, nonceFile)
	if err != nil {
		fmt.Println("Attestation error:", err)
		os.Exit(1)
	}

	var result []byte
	if prettyPrint {
		result, err = json.MarshalIndent(q, "", "    ")
	} else {
		result, err = json.Marshal(q)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(result))
}
