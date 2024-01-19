package main

import (
	"log"
	"os"
)

func main() {
	p15Bytes, err := os.ReadFile("./apc9138a8cert-no-header.p15")
	if err != nil {
		panic(err)
	}

	apcHeader, err := makeFileHeader(p15Bytes)
	if err != nil {
		panic(err)
	}

	wizardBytes, err := os.ReadFile("./apc9138a.apc-wizard.p15")
	if err != nil {
		panic(err)
	}

	wizHeader := wizardBytes[:228]

	log.Println(apcHeader)
	log.Println(wizHeader)

	for i := range wizHeader {
		if apcHeader[i] != wizHeader[i] {
			panic(i)
		}
	}

	log.Println("match")

}
