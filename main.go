package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"tpm2-quote-attest/tool"
)

func main() {
	var messageFilePath, pcrFilePath, pubKeyFilePath, signatureFilePath, nonceFilePath string
	var prettyPrint bool
	flag.StringVar(&messageFilePath, "message-file", "", "Path to message file")
	flag.StringVar(&pcrFilePath, "pcr-file", "", "Path to pcr file (in pcrs_format=values)")
	flag.StringVar(&pubKeyFilePath, "pubKey-file", "", "Path to public key file")
	flag.StringVar(&signatureFilePath, "signature-file", "", "Path to signature file")
	flag.StringVar(&nonceFilePath, "nonce-file", "", "Path to nonce file")
	flag.BoolVar(&prettyPrint, "pretty", true, "Pretty-print JSON output")
	flag.Parse()

	if flag.NFlag() < 5 {
		flag.Usage()
		os.Exit(1)
	}

	var err error

	// ---------------------------- Read Files --------------------------------
	messageFile, err := os.ReadFile(messageFilePath)
	if err != nil {
		log.Fatal(err)
	}

	pcrFile, err := os.ReadFile(pcrFilePath)
	if err != nil {
		log.Fatal(err)
	}

	pubKeyFile, err := os.ReadFile(pubKeyFilePath)
	if err != nil {
		log.Fatal(err)
	}

	signatureFile, err := os.ReadFile(signatureFilePath)
	if err != nil {
		log.Fatal(err)
	}

	nonceFile, err := os.ReadFile(nonceFilePath)
	if err != nil {
		log.Fatal(err)
	}
	// ------------------------------------------------------------------------

	q, err := tool.Attest(pubKeyFile, messageFile, pcrFile, signatureFile, nonceFile)
	if err != nil {
		log.Fatal(err)
	}

	var result []byte
	if prettyPrint {
		result, err = json.MarshalIndent(q, "", "    ")
	} else {
		result, err = json.Marshal(q)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(result))
}
