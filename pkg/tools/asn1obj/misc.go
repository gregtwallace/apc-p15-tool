package asn1obj

import "encoding/asn1"

// Explicit wraps another ASN.1 Object with the EXPLICIT wrapper using
// the tag number specified
func Explicit(explicitTagNumber int, wrappedElement []byte) []byte {
	raw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        explicitTagNumber,
		IsCompound: true,
		Bytes:      wrappedElement,
	}

	// should never error
	asn1result, err := asn1.Marshal(raw)
	if err != nil {
		panic(err)
	}

	return asn1result
}

// Null returns the NULL value
func Null() []byte {
	return asn1.NullBytes
}
