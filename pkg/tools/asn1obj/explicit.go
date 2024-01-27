package asn1obj

import "encoding/asn1"

// ExplicitCompound wraps another ASN.1 Object(s) with the EXPLICIT wrapper using
// the tag number specified
func ExplicitCompound(explicitTagNumber int, wrappedElements [][]byte) []byte {
	val := []byte{}
	for i := range wrappedElements {
		val = append(val, wrappedElements[i]...)
	}

	raw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        explicitTagNumber,
		IsCompound: true,
		Bytes:      val,
	}

	// should never error
	asn1result, err := asn1.Marshal(raw)
	if err != nil {
		panic(err)
	}

	return asn1result
}

// ExplicitValue creates an EXPLICIT Object with a byte data value (i.e. it
// is NOT compound) using the tag number specified
func ExplicitValue(explicitTagNumber int, val []byte) []byte {
	raw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        explicitTagNumber,
		IsCompound: false,
		Bytes:      val,
	}

	// should never error
	asn1result, err := asn1.Marshal(raw)
	if err != nil {
		panic(err)
	}

	return asn1result
}
