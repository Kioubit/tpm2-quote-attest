package main

import (
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	b, err := ioutil.ReadFile("quote.out")
	if err != nil {
		log.Fatal(err.Error())
	}

	// Needs to be created using  -pcrs_format=values
	pcrFile, err := ioutil.ReadFile("quote.pcr")
	if err != nil {
		log.Fatal(err.Error())
	}

	result, err := MarshalRawQuoteMessage(b)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("Nonce", result.extraData.data)

	pcrSelection := result.attested.quote.pcrSelect.pcrSelections[0]

	fmt.Println("Algorithm used:", pcrSelection.hashAlgorithmID)

	q, err := ParseValuePcrFileWithList(pcrFile, GetPCRList(pcrSelection), CUSTOM_TPM_ALG{
		hashSize:  32,
		Algorithm: TPM_ALG_SHA256,
	})
	if err != nil {
		log.Fatal(err.Error())
	}

	err = VerifyQuoteDigest(q, result.attested.quote.pcrDigest.buffer)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Printf("%x", q)

}
