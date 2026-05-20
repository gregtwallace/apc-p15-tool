package asn1obj

// common struct for asn1 byte tests
type asn1ByteTest struct {
	content         []byte
	expectedEncoded []byte
}

// common struct for asn1 string tests
type asn1StringTest struct {
	content         string
	expectedEncoded []byte
	shouldPanic     bool
}
