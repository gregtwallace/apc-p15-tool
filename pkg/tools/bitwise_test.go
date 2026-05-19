package tools

import (
	"bytes"
	"testing"
)

type bytePair struct {
	bytes      []byte
	otherBytes []byte
}

// valid bitwise compliments
var areBitwiseCompliments = []bytePair{
	{
		bytes:      []byte{0x88, 0x00, 0xff, 0x0, 0x00, 0x1, 0x01},
		otherBytes: []byte{0x77, 0xff, 0x00, 0xff, 0xff, 0xfe, 0xfe},
	},
	{
		bytes:      []byte{0x00, 0x00, 0x00, 0x01, 0xfe, 0x44, 0x55},
		otherBytes: []byte{0xff, 0xff, 0xff, 0xfe, 0x01, 0xbb, 0xaa},
	},
	{
		bytes:      []byte{},
		otherBytes: []byte{},
	},
}

// not compliments
// valid bitwise compliments
var notBitwiseCompliments = []bytePair{
	{
		bytes:      []byte{0x77, 0x00, 0xff, 0x0, 0x00, 0x1, 0x01},
		otherBytes: []byte{0x77, 0xff, 0x00, 0xff, 0xff, 0xfe, 0xfe},
	},
	{
		bytes:      []byte{0x00, 0x00, 0x00, 0x01, 0xfe, 0x44, 0x55},
		otherBytes: []byte{0xff, 0xff, 0xff, 0xfe, 0x01, 0xaa, 0xaa},
	},
	{
		bytes:      []byte{0xff},
		otherBytes: []byte{},
	},
	{
		bytes:      []byte{},
		otherBytes: []byte{0x00},
	},
}

// BitwiseComplementOf tests
func TestBitwiseCompliment(t *testing.T) {
	for i := range areBitwiseCompliments {
		out := BitwiseComplimentOf(areBitwiseCompliments[i].bytes)
		if !bytes.Equal(out, areBitwiseCompliments[i].otherBytes) {
			t.Errorf("bitwise compliment of %X expected %X but got %X", areBitwiseCompliments[i].bytes, areBitwiseCompliments[i].otherBytes, out)
		}
	}
}

// IsBitwiseCompliment tests
func TestIsBitwiseCompliment(t *testing.T) {
	// should return true
	for i := range areBitwiseCompliments {
		result := IsBitwiseCompliment(areBitwiseCompliments[i].bytes, areBitwiseCompliments[i].otherBytes)
		if !result {
			t.Errorf("expected true for bitwise check of %X vs. %X", areBitwiseCompliments[i].bytes, areBitwiseCompliments[i].otherBytes)
		}
	}

	// should return false
	for i := range notBitwiseCompliments {
		result := IsBitwiseCompliment(notBitwiseCompliments[i].bytes, notBitwiseCompliments[i].otherBytes)
		if result {
			t.Errorf("expected false for bitwise check of %X vs. %X", notBitwiseCompliments[i].bytes, notBitwiseCompliments[i].otherBytes)
		}
	}
}
