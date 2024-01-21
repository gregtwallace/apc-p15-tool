package main

import (
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// makeKEK creates the APC KEK for a given Salt; APC uses a fixed
// password, iteration count, and hash function
func makeKEK(salt []byte) (KEK []byte) {
	// password is known constant for APC files
	password := "user"

	// fixed values for APC files
	iterations := 5000
	hash := sha256.New

	// size of 3DES key (k1 + k2 + k3)
	size := 24

	// kek
	return pbkdf2.Key([]byte(password), salt, iterations, size, hash)
}
