package asn1obj

import (
	"encoding/asn1"
)

// BitString returns a BIT STRING of the exact sequence of 1s and 0s specified.
// if the string contains any char other than 1 or 0, it panics
func BitString(bits string) []byte {
	// convert to bytes
	bytes := []byte{}
	endingPos := 0

	for _, c := range bits {
		// panic if invalid char
		if c != '0' && c != '1' {
			panic("asn1obj: BitString was called with an invalid string")
		}

		// endingPos 0 is time to add another byte
		if endingPos == 0 {
			bytes = append(bytes, byte(0))
		}

		// add a bit by left shifting
		bytes[len(bytes)-1] = bytes[len(bytes)-1] << 1

		// if new bit is a 1, make it so
		if c == '1' {
			bytes[len(bytes)-1] = bytes[len(bytes)-1] + 1
		}

		// increment position
		endingPos++

		// is this byte done?
		if endingPos == 8 {
			endingPos = 0
		}
	}

	// add padding 0s to end
	if endingPos != 0 {
		bytes[len(bytes)-1] = bytes[len(bytes)-1] << (8 - endingPos)
	}

	bs := asn1.BitString{
		Bytes:     bytes,
		BitLength: len(bytes)*8 - (8 - endingPos),
	}

	// should never error
	asn1result, err := asn1.Marshal(bs)
	if err != nil {
		panic("asn1obj: BitString failed to marshal " + err.Error())
	}

	return asn1result
}

// BitStringFromBytes returns a BIT STRING from byte data
func BitStringFromBytes(content []byte) []byte {
	bs := asn1.BitString{
		Bytes:     content,
		BitLength: len(content) * 8,
	}

	// should never error
	asn1result, err := asn1.Marshal(bs)
	if err != nil {
		panic("asn1obj: BitStringFromBytes failed to marshal " + err.Error())
	}

	return asn1result
}
