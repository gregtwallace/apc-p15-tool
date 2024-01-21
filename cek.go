package main

import (
	"crypto/cipher"
	"crypto/des"
	"errors"
	"fmt"
)

// decryptCEK decrypts the encrypted CEK and unwraps the CEK so only the
// original CEK is returned
func decryptCEK(encryptedCEK, encryptedCekSalt, KEK []byte) (CEK []byte, err error) {
	// ensure proper var lens, or error
	encryptedCEKLen := 24
	CEKSaltLen := 8
	KEKLen := 24

	if len(encryptedCEK) != encryptedCEKLen {
		return nil, errors.New("wrong encrypted CEK length")
	}
	if len(encryptedCekSalt) != CEKSaltLen {
		return nil, errors.New("wrong encrypted CEK's salt length")
	}
	if len(KEK) != KEKLen {
		return nil, errors.New("wrong KEK length")
	}

	// 3DES uses block byte size of 8
	blockByteSize := 8

	// make DES cipher from KEK
	kekDesCipher, err := des.NewTripleDESCipher(KEK)
	if err != nil {
		return nil, fmt.Errorf("failed to make DES cipher for cek decryption (%s)", err)
	}

	// (1) first use n-1'th block as IV to decrypt n'th block
	ivStart := encryptedCEKLen - 2*blockByteSize
	ivEnd := encryptedCEKLen - 1*blockByteSize

	ivBlockCipherText := encryptedCEK[ivStart:ivEnd]
	nthBlockCipherText := encryptedCEK[encryptedCEKLen-1*blockByteSize:]

	firstBlockDecrypter := cipher.NewCBCDecrypter(kekDesCipher, ivBlockCipherText)

	decryptedNthBlock := make([]byte, len(nthBlockCipherText))
	firstBlockDecrypter.CryptBlocks(decryptedNthBlock, nthBlockCipherText)

	// (2) decrypt remainder of outer encryption blocks (1 ... n-1'th) using
	// the decrypted nthBlock as the IV
	outerRemainderDecrypter := cipher.NewCBCDecrypter(kekDesCipher, decryptedNthBlock)

	decryptedOuterRemainder := make([]byte, encryptedCEKLen-1*blockByteSize)
	outerRemainderDecrypter.CryptBlocks(decryptedOuterRemainder, encryptedCEK[:encryptedCEKLen-1*blockByteSize])

	// combine decrypted remainder with decrypted nth block for complete decrypted bytes
	// this is equivelant to having the outer encryption removed, AKA the CEK is encrypted
	// once now instead of twice
	onceEncryptedCEK := append(decryptedOuterRemainder, decryptedNthBlock...)

	// (3) Decrypted the inner layer of encryption using the KEK (aka decrypt the remaining
	// layer of encryption)

	// inner decrypter uses original CEK salt
	innerDecrypter := cipher.NewCBCDecrypter(kekDesCipher, encryptedCekSalt)

	// once decrypted, the CEK is still formatted as:
	// CEK byte count || check value || CEK || padding (if required)
	formattedCEK := make([]byte, len(onceEncryptedCEK))
	innerDecrypter.CryptBlocks(formattedCEK, onceEncryptedCEK)

	// Now that CEK is decrypted, sanity check it

	// first byte is CEK byte count
	expectedCEKLen := formattedCEK[0]

	// (1a) expected cek len must be 16 or 24 or 3DES (which is what APC uses)
	if int(expectedCEKLen) != 16 && int(expectedCEKLen) != 24 {
		return nil, errors.New("expected CEK len block size is %d but 3DES requires 16 or 24 (decrypting likely failed)")
	}

	// next 3 bytes are the check value
	CEKCheckVal := formattedCEK[1:4]

	// CEK itself is the next bytes until CEK is the expected length
	CEK = formattedCEK[4 : expectedCEKLen+4]

	// (1b) key check data validation
	if !isBitwiseCompliment(CEKCheckVal, CEK[0:3]) {
		return nil, errors.New("CEK check value did not match CEK")
	}

	return CEK, nil
}
