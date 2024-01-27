package pkcs15

import (
	"apc-p15-tool/pkg/tools/asn1obj"
	"crypto/sha1"
	"encoding/binary"
	"math/big"
)

// keyId returns the keyId for the overall key object
func (p15 *pkcs15KeyCert) keyId() []byte {
	// object to hash is just the RawSubjectPublicKeyInfo

	// Create Object to hash
	// hashObj := asn1obj.Sequence([][]byte{
	// 	asn1obj.Sequence([][]byte{
	// 		// Key is RSA
	// 		asn1obj.ObjectIdentifier(asn1obj.OIDrsaEncryptionPKCS1),
	// 		asn1.NullBytes,
	// 	}),
	// 	// BIT STRING of rsa key public key
	// 	asn1obj.BitString(
	// 		asn1obj.Sequence([][]byte{
	// 			asn1obj.Integer(p15.key.N),
	// 			asn1obj.Integer((big.NewInt(int64(p15.key.E)))),
	// 		}),
	// 	),
	// })

	// SHA-1 Hash
	hasher := sha1.New()
	_, err := hasher.Write(p15.cert.RawSubjectPublicKeyInfo)
	if err != nil {
		panic(err)
	}

	return hasher.Sum(nil)
}

// keyIdInt2 returns the sequence for keyId with INT val of 2
// For APC, this appears to be the same value is the base keyId
// but this isn't compliant with the spec which actually seems
// to call for SKID (skid octet value copied directly out of the
// certificate's x509 extension)
func (p15 *pkcs15KeyCert) keyIdInt2() []byte {
	// Create Object
	obj := asn1obj.Sequence([][]byte{
		asn1obj.Integer(big.NewInt(2)),
		// Note: This is for APC, doesn't seem compliant with spec though
		asn1obj.OctetString(p15.keyId()),
	})

	return obj
}

// keyIdInt3 returns the sequence for keyId with INT val of 3; This value is equivelant
// to "issuerAndSerialNumberHash" and rfc defines IssuerAndSerialNumber SEQUENCE:
// https://datatracker.ietf.org/doc/html/rfc3852#section-10.2.4
func (p15 *pkcs15KeyCert) keyIdInt3() []byte {
	// object to hash
	hashObj := asn1obj.Sequence([][]byte{
		// issuerDistinguishedName
		p15.cert.RawIssuer,
		// serialNumber
		asn1obj.Integer(p15.cert.SerialNumber),
	})

	// SHA-1 Hash
	hasher := sha1.New()
	_, err := hasher.Write(hashObj)
	if err != nil {
		panic(err)
	}

	// object to return
	obj := asn1obj.Sequence([][]byte{
		asn1obj.Integer(big.NewInt(3)),
		asn1obj.OctetString(hasher.Sum(nil)),
	})

	return obj
}

// keyIdInt6 returns the sequence for keyId with INT val of 6; This value is equivelant
// to "issuerNameHash"
func (p15 *pkcs15KeyCert) keyIdInt6() []byte {
	// object to hash is just the RawIssuer

	// SHA-1 Hash
	hasher := sha1.New()
	_, err := hasher.Write(p15.cert.RawIssuer)
	if err != nil {
		panic(err)
	}

	// object to return
	obj := asn1obj.Sequence([][]byte{
		asn1obj.Integer(big.NewInt(6)),
		asn1obj.OctetString(hasher.Sum(nil)),
	})

	return obj
}

// keyIdInt7 returns the sequence for keyId with INT val of 7; This value is equivelant
// to "subjectNameHash"
func (p15 *pkcs15KeyCert) keyIdInt7() []byte {
	// object to hash is just the RawIssuer

	// SHA-1 Hash
	hasher := sha1.New()
	_, err := hasher.Write(p15.cert.RawSubject)
	if err != nil {
		panic(err)
	}

	// object to return
	obj := asn1obj.Sequence([][]byte{
		asn1obj.Integer(big.NewInt(7)),
		asn1obj.OctetString(hasher.Sum(nil)),
	})

	return obj
}

// keyIdInt8 returns the sequence for keyId with INT val of 8; This value is equivelant
// to "pgp", which is PGP v3 key Id. This value is just the last 8 bytes of the public
// key N value
func (p15 *pkcs15KeyCert) keyIdInt8() []byte {
	nBytes := p15.key.N.Bytes()

	// object to return
	obj := asn1obj.Sequence([][]byte{
		asn1obj.Integer(big.NewInt(8)),
		asn1obj.OctetString(nBytes[len(nBytes)-8:]),
	})

	return obj
}

// bigIntToMpi returns the MPI (as defined in RFC 4880 s 3.2) from a given
// big.Int; this is used as a helper for key ID 9 (openPGP)
func bigIntToMpi(i *big.Int) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(i.BitLen()))

	return append(length, i.Bytes()...)
}

// keyIdInt9 returns the sequence for keyId with INT val of 9; This value is equivelant
// to "openPGP", which is PGP v4 key Id.
// see: https://www.rfc-editor.org/rfc/rfc4880.html s 12.2
func (p15 *pkcs15KeyCert) keyIdInt9() []byte {
	// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
	// followed by the two-octet packet length, followed by the entire
	// Public-Key packet starting with the version field.  The Key ID is the
	// low-order 64 bits of the fingerprint.

	// the entire Public-Key packet
	publicKeyPacket := []byte{}

	// starting with the version field (A one-octet version number (4)).
	publicKeyPacket = append(publicKeyPacket, byte(4))

	// A four-octet number denoting the time that the key was created.
	time := make([]byte, 4)

	// NOTE: use cert validity start as proxy for key creation since key pem
	// doesn't actually contain a created at time -- in reality notBefore tends
	// to be ~ 1 hour ish BEFORE the cert was even created. Key would also
	// obviously have to be created prior to the cert creation.
	binary.BigEndian.PutUint32(time, uint32(p15.cert.NotBefore.Unix()))
	publicKeyPacket = append(publicKeyPacket, time...)

	// A one-octet number denoting the public-key algorithm of this key.
	// 1 - RSA (Encrypt or Sign) [HAC]
	publicKeyPacket = append(publicKeyPacket, byte(1))

	// Algorithm-Specific Fields for RSA public keys:
	// multiprecision integer (MPI) of RSA public modulus n
	publicKeyPacket = append(publicKeyPacket, bigIntToMpi(p15.key.N)...)

	// MPI of RSA public encryption exponent e
	e := big.NewInt(int64(p15.key.PublicKey.E))
	publicKeyPacket = append(publicKeyPacket, bigIntToMpi(e)...)

	// Assemble the V4 byte array that will be hashed
	// 0x99 (1 octet)
	toHash := []byte{0x99}

	// big endian encoded length of public key packet (2 octets)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(publicKeyPacket)))
	toHash = append(toHash, length...)

	// Public-Key packet
	toHash = append(toHash, publicKeyPacket...)

	// SHA-1 Hash (Fingerprint)
	hasher := sha1.New()
	hasher.Write(toHash)
	sha1Hash := hasher.Sum(nil)

	// keyId is lower 64 bits (8 bytes)
	keyId := sha1Hash[len(sha1Hash)-8:]

	// object to return
	obj := asn1obj.Sequence([][]byte{
		asn1obj.Integer(big.NewInt(9)),
		asn1obj.OctetString(keyId),
	})

	return obj
}
