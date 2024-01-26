package asn1obj

import "encoding/asn1"

var (
	OIDPkscs15Content     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 15, 3, 1} // pkcs15content (PKCS #15 content type)
	OIDrsaEncryptionPKCS1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}     // rsaEncryption (PKCS #1)
)

// ObjectIdentifier returns an ASN.1 OBJECT IDENTIFIER with the oidValue bytes
func ObjectIdentifier(oid asn1.ObjectIdentifier) []byte {
	// should never error
	asn1result, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}

	return asn1result
}
