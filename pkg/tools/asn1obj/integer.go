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

// IntegerExplicitValue returns bigInt encoded as an Integer, however
// instead of tagging it with Integer it is instead tagged with an
// explicit tag of the specified tag number
func IntegerExplicitValue(explicitTagNumber int, bigInt *big.Int) []byte {
	intBytes := Integer(bigInt)

	asn1Obj := asn1.RawValue{}
	rest, err := asn1.Unmarshal(intBytes, &asn1Obj)
	if err != nil {
		panic(err)
	} else if len(rest) > 0 {
		panic("invalid extra data")
	}

	return ExplicitValue(explicitTagNumber, asn1Obj.Bytes)
}
