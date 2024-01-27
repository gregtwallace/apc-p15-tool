package asn1obj

import "encoding/asn1"

// Set returns an ASN.1 SET with the specified content
func Set(content [][]byte) []byte {
	val := []byte{}
	for i := range content {
		val = append(val, content[i]...)
	}

	raw := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
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
