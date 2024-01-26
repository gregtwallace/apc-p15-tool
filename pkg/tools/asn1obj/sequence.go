package asn1obj

import "encoding/asn1"

// Sequence returns an ASN.1 SEQUENCE with the specified content
func Sequence(content [][]byte) []byte {
	val := []byte{}
	for i := range content {
		val = append(val, content[i]...)
	}

	raw := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
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
