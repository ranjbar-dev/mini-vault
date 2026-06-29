// vault-encrypt: pre-build CLI that encrypts data/secrets.json → data/secrets.bin.
// Run on an offline workstation before building the mini-vault binary.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	version2  = uint16(0x0002)
	argonMem  = uint32(262144) // 256 MB in KB
	argonIter = uint32(3)
	argonPar  = uint8(2)
)

func main() {
	inPath := flag.String("in", "data/secrets.json", "input secrets JSON file")
	outPath := flag.String("out", "data/secrets.bin", "output encrypted file")
	flag.Parse()

	// Read and validate JSON
	jsonBytes, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read %s: %v\n", *inPath, err)
		os.Exit(1)
	}

	var secrets map[string]string
	if err := json.Unmarshal(jsonBytes, &secrets); err != nil {
		fmt.Fprintln(os.Stderr, "invalid JSON: must be a flat map[string]string")
		os.Exit(1)
	}
	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "secrets file is empty")
		os.Exit(1)
	}

	// Prompt passphrase twice (constant-time comparison)
	fmt.Fprint(os.Stderr, "Enter passphrase: ")
	pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading passphrase")
		os.Exit(1)
	}

	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		zero(pass1)
		fmt.Fprintln(os.Stderr, "error reading passphrase")
		os.Exit(1)
	}

	if subtle.ConstantTimeCompare(pass1, pass2) != 1 {
		zero(pass1)
		zero(pass2)
		fmt.Fprintln(os.Stderr, "passphrases do not match")
		os.Exit(1)
	}
	zero(pass2)

	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		zero(pass1)
		fmt.Fprintln(os.Stderr, "failed to generate salt")
		os.Exit(1)
	}

	// Derive wrapping key via Argon2id
	unwrap := argon2.IDKey(pass1, salt, argonIter, argonMem, argonPar, 32)
	zero(pass1)

	// Encrypt JSON bytes with AES-256-GCM
	block, err := aes.NewCipher(unwrap)
	zero(unwrap)
	if err != nil {
		fmt.Fprintln(os.Stderr, "internal error")
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Fprintln(os.Stderr, "internal error")
		os.Exit(1)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		fmt.Fprintln(os.Stderr, "failed to generate nonce")
		os.Exit(1)
	}

	// Re-marshal to canonical JSON
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		fmt.Fprintln(os.Stderr, "internal error")
		os.Exit(1)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	zero(plaintext)

	// Build output: [version|salt|memKB|iters|threads|nonce|ciphertext+tag]
	header := make([]byte, 39)
	off := 0
	binary.BigEndian.PutUint16(header[off:], version2)
	off += 2
	copy(header[off:], salt)
	off += 16
	binary.BigEndian.PutUint32(header[off:], argonMem)
	off += 4
	binary.BigEndian.PutUint32(header[off:], argonIter)
	off += 4
	header[off] = argonPar
	off++
	copy(header[off:], nonce)

	out := append(header, sealed...)

	if err := os.WriteFile(*outPath, out, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %d bytes to %s\n", len(out), *outPath)
	fmt.Println("data/secrets.bin is safe to commit to your private repo (encrypted).")
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
