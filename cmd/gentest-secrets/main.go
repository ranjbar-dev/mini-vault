// gentest-secrets: generates a test data/secrets.bin for local dev/CI only.
// NOT for production — the passphrase and secret values are hardcoded and public.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
)

const testPassphrase = "test-passphrase-change-before-production"

func main() {
	fmt.Fprintln(os.Stderr, "WARNING: This generates TEST-ONLY secrets. Do NOT use in production.")

	secrets := map[string]string{
		"kek":         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"db_password": "hunter2",
		"api_key":     "sk-test-abc123",
	}

	// Write data/secrets.json (for reference; gitignored)
	jsonBytes, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll("data", 0700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("data/secrets.json", jsonBytes, 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("data/secrets.json written (TEST ONLY)")

	passphrase := []byte(testPassphrase)

	salt := make([]byte, 16)
	rand.Read(salt) //nolint:errcheck

	memKB := uint32(262144)
	iters := uint32(3)
	par := uint8(2)

	unwrap := argon2.IDKey(passphrase, salt, iters, memKB, par, 32)
	for i := range passphrase {
		passphrase[i] = 0
	}

	plaintext, _ := json.Marshal(secrets)

	block, _ := aes.NewCipher(unwrap)
	for i := range unwrap {
		unwrap[i] = 0
	}
	gcm, _ := cipher.NewGCM(block)

	nonce := make([]byte, 12)
	rand.Read(nonce) //nolint:errcheck

	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	for i := range plaintext {
		plaintext[i] = 0
	}

	header := make([]byte, 39)
	off := 0
	binary.BigEndian.PutUint16(header[off:], 0x0002)
	off += 2
	copy(header[off:], salt)
	off += 16
	binary.BigEndian.PutUint32(header[off:], memKB)
	off += 4
	binary.BigEndian.PutUint32(header[off:], iters)
	off += 4
	header[off] = par
	off++
	copy(header[off:], nonce)

	out := append(header, sealed...)

	if err := os.WriteFile("data/secrets.bin", out, 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("data/secrets.bin written (TEST ONLY — regenerate with vault-encrypt before production)")
	fmt.Printf("Test passphrase: %s\n", testPassphrase)
}
