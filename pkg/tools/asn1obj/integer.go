package asn1obj

import (
	"encoding/asn1"
	"math/big"
)

// Integer returns an ASN.1 OBJECT IDENTIFIER with the oidValue bytes
func Integer(bigInt *big.Int) []byte {
	// should never error
	asn1result, err := asn1.Marshal(bigInt)
	if err != nil {
		panic(err)
	}

	return asn1result
}
