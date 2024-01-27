package asn1obj

import "encoding/asn1"

var (
	OIDPkscs15Content     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 15, 3, 1}     // pkcs15content (PKCS #15 content type)
	OIDrsaEncryptionPKCS1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}         // rsaEncryption (PKCS #1)
	OIDpkcs5PBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}        // pkcs5PBKDF2 (PKCS #5 v2.0)
	OIDhmacWithSHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}            // hmacWithSHA256 (RSADSI digestAlgorithm)
	OIDpwriKEK            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 9}  // pwriKEK (S/MIME Algorithms)
	OIDdesEDE3CBC         = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}            // des-EDE3-CBC (RSADSI encryptionAlgorithm)
	OIDpkcs7Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}         // data (PKCS #7)
	OIDauthEnc128         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 3, 15} // authEnc128 (S/MIME Algorithms)
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
