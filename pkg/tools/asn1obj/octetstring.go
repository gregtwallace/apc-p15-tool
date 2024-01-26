package asn1obj

import (
	"encoding/asn1"
)

// OctetString returns an OCTET STRING of the content
func OctetString(content []byte) []byte {
	raw := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagOctetString,
		IsCompound: false,
		Bytes:      content,
	}

	// should never error
	asn1result, err := asn1.Marshal(raw)
	if err != nil {
		panic(err)
	}

	return asn1result
}
