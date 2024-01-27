package pkcs15

import "apc-p15-tool/pkg/tools/asn1obj"

// privateKeyObject returns the ASN.1 representation of a private key
func (p15 *pkcs15KeyCert) privateKeyObject() []byte {
	// ensure all expected vals are available
	p15.key.Precompute()

	pkey := asn1obj.Sequence([][]byte{
		// P
		asn1obj.IntegerExplicitValue(3, p15.key.Primes[0]),
		// Q
		asn1obj.IntegerExplicitValue(4, p15.key.Primes[1]),
		// Dp
		asn1obj.IntegerExplicitValue(5, p15.key.Precomputed.Dp),
		// Dq
		asn1obj.IntegerExplicitValue(6, p15.key.Precomputed.Dq),
		// Qinv
		asn1obj.IntegerExplicitValue(7, p15.key.Precomputed.Qinv),
	})

	return pkey
}
