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

	result, err := MarshalRawQuoteMessage(b)
	if err != nil {
		log.Fatal(err.Error())
	}

	fmt.Println("Digest", result.attested.quote.pcrDigest)
	fmt.Println("Nonce", result.extraData.data)

}
