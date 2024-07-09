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
	OIDecPublicKey        = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}             // ecPublicKey (ANSI X9.62 public key type)
	OIDprime256v1         = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}          //  prime256v1 (ANSI X9.62 named elliptic curve)
	OIDsecp384r1          = asn1.ObjectIdentifier{1, 3, 132, 0, 34}                   //  secp384r1 (SECG (Certicom) named elliptic curve)
	OIDsecp521r1          = asn1.ObjectIdentifier{1, 3, 132, 0, 35}                   //  secp521r1 (SECG (Certicom) named elliptic curve)
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
