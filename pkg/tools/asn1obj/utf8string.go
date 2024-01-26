package asn1obj

import (
	"encoding/asn1"
)

// UTF8String returns the specified string as a UTF8String
func UTF8String(s string) []byte {
	// should never error
	asn1result, err := asn1.MarshalWithParams(s, "utf8")
	if err != nil {
		panic(err)
	}

	return asn1result
}
