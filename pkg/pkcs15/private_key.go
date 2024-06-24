package pkcs15

import (
	"apc-p15-tool/pkg/tools/asn1obj"
	"crypto/rsa"
)

// privateKeyObject returns the ASN.1 representation of a private key
func (p15 *pkcs15KeyCert) privateKeyObject() []byte {
	var privKeyObj []byte

	switch privKey := p15.key.(type) {
	case *rsa.PrivateKey:
		privKey.Precompute()

		// ensure all expected vals are available
		privKeyObj = asn1obj.Sequence([][]byte{
			// P
			asn1obj.IntegerExplicitValue(3, privKey.Primes[0]),
			// Q
			asn1obj.IntegerExplicitValue(4, privKey.Primes[1]),
			// Dp
			asn1obj.IntegerExplicitValue(5, privKey.Precomputed.Dp),
			// Dq
			asn1obj.IntegerExplicitValue(6, privKey.Precomputed.Dq),
			// Qinv
			asn1obj.IntegerExplicitValue(7, privKey.Precomputed.Qinv),
		})

	// case *ecdsa.PrivateKey:
	// 	// Only private piece is the integer D
	// 	privKeyObj = asn1obj.Sequence([][]byte{
	// 		asn1obj.Integer(privKey.D),
	// 	})

	default:
		// panic if non-RSA key
		panic("private key object for non-rsa key is unexpected and unsupported")
	}

	return privKeyObj
}
