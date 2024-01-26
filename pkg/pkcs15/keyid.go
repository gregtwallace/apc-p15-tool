package pkcs15

import (
	"apc-p15-tool/pkg/tools/asn1obj"
	"crypto/sha1"
	"math/big"
)

// keyId returns the keyId for the overall key object
func (p15 *pkcs15KeyCert) keyId() []byte {
	// Create Object to hash
	hashObj := asn1obj.Sequence([][]byte{
		asn1obj.Sequence([][]byte{
			// Key is RSA
			asn1obj.ObjectIdentifier(asn1obj.OIDrsaEncryptionPKCS1),
			asn1obj.Null(),
		}),
		// BIT STRING of rsa key public key
		asn1obj.BitString(
			asn1obj.Sequence([][]byte{
				asn1obj.Integer(p15.key.N),
				asn1obj.Integer((big.NewInt(int64(p15.key.E)))),
			}),
		),
	})

	// SHA-1 Hash
	hasher := sha1.New()
	_, err := hasher.Write(hashObj)
	if err != nil {
		panic(err)
	}

	return hasher.Sum(nil)
}
