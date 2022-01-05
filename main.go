package main

import (
	"fmt"
	"io/ioutil"
)

func main() {
	b, err := ioutil.ReadFile("quote.out")
	if err != nil {
		fmt.Print(err)
	}
	_, err = MarshalRawQuoteMessage(b)
	if err != nil {
		fmt.Println(err.Error())
	}
}
