// gentest-kek: generates a test kek.bin for local dev/CI only.
// NOT for production — use vault-keygen with a strong passphrase.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

func main() {
	passphrase := []byte("test-passphrase-change-before-production")

	salt := make([]byte, 16)
	rand.Read(salt) //nolint:errcheck

	unwrap := argon2.IDKey(passphrase, salt, 3, 262144, 2, 32)
	for i := range passphrase {
		passphrase[i] = 0
	}

	kekPlain := make([]byte, 32)
	rand.Read(kekPlain) //nolint:errcheck

	block, _ := aes.NewCipher(unwrap)
	for i := range unwrap {
		unwrap[i] = 0
	}
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, 12)
	rand.Read(nonce) //nolint:errcheck

	sealed := gcm.Seal(nil, nonce, kekPlain, nil)

	var buf [87]byte
	off := 0
	binary.BigEndian.PutUint16(buf[off:], 0x0001)
	off += 2
	copy(buf[off:], salt)
	off += 16
	binary.BigEndian.PutUint32(buf[off:], 262144)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], 3)
	off += 4
	buf[off] = 2
	off++
	copy(buf[off:], nonce)
	off += 12
	copy(buf[off:], sealed)

	if err := os.WriteFile("keys/kek.bin", buf[:], 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for i := range kekPlain {
		kekPlain[i] = 0
	}
	fmt.Println("keys/kek.bin written (TEST ONLY — regenerate with vault-keygen before production)")
}
