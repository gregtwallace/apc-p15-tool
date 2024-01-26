package asn1obj

import (
	"encoding/asn1"
	"math/bits"
)

// BitString returns a BIT STRING of the content
func BitString(content []byte) []byte {
	bs := asn1.BitString{
		Bytes: content,
	}

	// drop trailing 0s by removing them from overall length
	if len(content) > 0 {
		trailing0s := bits.TrailingZeros8(content[len(content)-1])
		bs.BitLength = 8*len(content) - trailing0s
	}

	// should never error
	asn1result, err := asn1.Marshal(bs)
	if err != nil {
		panic(err)
	}

	return asn1result
}
