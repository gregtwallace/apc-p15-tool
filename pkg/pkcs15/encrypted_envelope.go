package pkcs15

import (
	"apc-p15-tool/pkg/tools"
	"apc-p15-tool/pkg/tools/asn1obj"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

// fixed specs for apc cert
const (
	apcKEKPassword   = "user"
	apcKEKIterations = 5000
)

// encryptedKeyEnvelope encrypts p15's rsa private key using the algorithms and
// params expected in the APC file. Salt values are always random.
func (p15 *pkcs15KeyCert) encryptedKeyEnvelope() ([]byte, error) {
	// calculate values for the object
	kekSalt := make([]byte, 8)
	_, err := rand.Read(kekSalt)
	if err != nil {
		return nil, err
	}

	// kek hash alg
	kekHash := sha256.New
	// size of 3DES key (k1 + k2 + k3)
	kekSize := 24

	// kek
	kek := pbkdf2.Key([]byte(apcKEKPassword), kekSalt, apcKEKIterations, kekSize, kekHash)

	// make DES cipher from KEK for CEK
	cekDesCipher, err := des.NewTripleDESCipher(kek)
	if err != nil {
		return nil, err
	}

	// cek (16 bytes for authEnc128) -- see: rfc3211
	cekLen := uint8(16)
	cek := make([]byte, cekLen)
	_, err = rand.Read(cek)
	if err != nil {
		return nil, err
	}

	// LEN + Check Val [3]
	wrappedCEK := append([]byte{cekLen}, tools.BitwiseComplimentOf(cek[:3])...)

	// + CEK
	wrappedCEK = append(wrappedCEK, cek...)

	// + padding (if needed)
	// pad wrapped CEK to min 2 * block len
	cekPadLen := 0
	if len(wrappedCEK) < 2*cekDesCipher.BlockSize() {
		cekPadLen = 2*cekDesCipher.BlockSize() - len(wrappedCEK)
	} else if len(wrappedCEK)%cekDesCipher.BlockSize() != 0 {
		// pad if not a multiple of block len
		cekPadLen = cekDesCipher.BlockSize() - len(wrappedCEK)%cekDesCipher.BlockSize()
	}
	cekPadding := make([]byte, cekPadLen)
	_, err = rand.Read(cekPadding)
	if err != nil {
		return nil, err
	}

	wrappedCEK = append(wrappedCEK, cekPadding...)

	// double encrypt CEK
	cekEncryptSalt := make([]byte, 8)
	_, err = rand.Read(cekEncryptSalt)
	if err != nil {
		return nil, err
	}

	cekEncrypter := cipher.NewCBCEncrypter(cekDesCipher, cekEncryptSalt)

	encryptedCEKOnly1Rd := make([]byte, len(wrappedCEK))
	cekEncrypter.CryptBlocks(encryptedCEKOnly1Rd, wrappedCEK)
	encryptedCEK := make([]byte, len(encryptedCEKOnly1Rd))
	cekEncrypter.CryptBlocks(encryptedCEK, encryptedCEKOnly1Rd)

	// content encryption
	contentEncSalt := make([]byte, 8)
	_, err = rand.Read(contentEncSalt)
	if err != nil {
		return nil, err
	}

	contentEncryptKey := pbkdf2.Key(cek, []byte("encryption"), 1, 24, sha1.New)
	contentDesCipher, err := des.NewTripleDESCipher(contentEncryptKey)
	if err != nil {
		return nil, err
	}

	// envelope content (that will be encrypted)
	content := p15.privateKeyObject()

	// pad content, see: https://datatracker.ietf.org/doc/html/rfc3852 6.3
	contentPadLen := uint8(contentDesCipher.BlockSize() - (len(content) % contentDesCipher.BlockSize()))
	// ALWAYS pad, if content is exact, add full block of padding
	if contentPadLen == 0 {
		contentPadLen = uint8(contentDesCipher.BlockSize())
	}
	for i := uint8(1); i <= contentPadLen; i++ {
		content = append(content, byte(contentPadLen))
	}

	contentEncrypter := cipher.NewCBCEncrypter(contentDesCipher, contentEncSalt)
	encryptedContent := make([]byte, len(content))
	contentEncrypter.CryptBlocks(encryptedContent, content)

	// data encryption alg block
	encAlgObj := asn1obj.Sequence([][]byte{
		// ContentEncryptionAlgorithmIdentifier
		asn1obj.ObjectIdentifier(asn1obj.OIDauthEnc128),
		// ContentEncryptionAlgorithmIdentifier details/info
		asn1obj.Sequence([][]byte{
			// encryption alg & salt
			asn1obj.Sequence([][]byte{
				// encryption alg
				asn1obj.ObjectIdentifier(asn1obj.OIDdesEDE3CBC),
				// encryption alg's salt
				asn1obj.OctetString(contentEncSalt),
			}),
			// mac alg
			asn1obj.Sequence([][]byte{
				asn1obj.ObjectIdentifier(asn1obj.OIDhmacWithSHA256),
				asn1.NullBytes,
			}),
		}),
	})

	// encrypted content MAC
	macKey := pbkdf2.Key(cek, []byte("authentication"), 1, 32, sha1.New)

	macHasher := hmac.New(sha256.New, macKey)
	// the data the MAC covers is the algId header bytes + encrypted data bytes
	hashMe := append(encAlgObj, encryptedContent...)

	// make MAC
	_, err = macHasher.Write(hashMe)
	if err != nil {
		return nil, err
	}
	mac := macHasher.Sum(nil)

	// build object
	// AuthEnvelopedData Type
	envelope := [][]byte{
		// CMSVersion
		asn1obj.Integer(big.NewInt(2)),
		// RecipientInfos
		asn1obj.Set([][]byte{
			// 1st and only 'RecipientInfo' - pwri [3] PasswordRecipientinfo
			asn1obj.ExplicitCompound(3, [][]byte{
				// CMSVersion
				asn1obj.Integer(big.NewInt(0)),
				// keyDerivationAlgorithm [0]
				asn1obj.ExplicitCompound(0, [][]byte{
					// KeyDerivationAlgorithmIdentifier
					asn1obj.ObjectIdentifier(asn1obj.OIDpkcs5PBKDF2),
					// KeyDerivationAlgorithmIdentifier details/info
					asn1obj.Sequence([][]byte{
						// kek pbkdf2 Salt
						asn1obj.OctetString(kekSalt),
						// kek pbkdf2 Iterations
						asn1obj.Integer(big.NewInt(apcKEKIterations)),
						// kek pbkdf2 hash type
						asn1obj.Sequence([][]byte{
							asn1obj.ObjectIdentifier(asn1obj.OIDhmacWithSHA256),
							asn1.NullBytes,
						}),
					}),
				}),
				// keyEncryptionAlgorithm (for CEK)
				asn1obj.Sequence([][]byte{
					// KeyEncryptionAlgorithmIdentifier
					asn1obj.ObjectIdentifier(asn1obj.OIDpwriKEK),
					// KeyEncryptionAlgorithmIdentifier details/info
					asn1obj.Sequence([][]byte{
						// encryption alg
						asn1obj.ObjectIdentifier(asn1obj.OIDdesEDE3CBC),
						// encryption alg's salt
						asn1obj.OctetString(cekEncryptSalt),
					}),
				}),
				// EncryptedKey (the actual ciphertext for the CEK)
				asn1obj.OctetString(encryptedCEK),
			}),
		}),
		// EncryptedContentInfo (actual encrypted content)
		asn1obj.Sequence([][]byte{
			// ContentType
			asn1obj.ObjectIdentifier(asn1obj.OIDpkcs7Data),
			// encryption alg OBJ
			encAlgObj,
			// [0] IMPLICIT EncryptedContent (AKA the ciphertext)
			asn1obj.ExplicitValue(0, encryptedContent),
		}),
		// MAC
		asn1obj.OctetString(mac),
	}

	// combine to singular byte slice
	finalEnv := []byte{}
	for i := range envelope {
		finalEnv = append(finalEnv, envelope[i]...)
	}

	return finalEnv, nil
}
