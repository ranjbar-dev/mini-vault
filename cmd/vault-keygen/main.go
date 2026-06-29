// vault-keygen: offline KEK generation tool.
// Run once on an offline workstation — never on a server.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	version1   = uint16(0x0001)
	argonMem   = uint32(262144) // 256 MB in KB
	argonIter  = uint32(3)
	argonPar   = uint8(2)
	kekBinLen  = 87
)

func main() {
	out := flag.String("out", "keys/kek.bin", "path to write kek.bin")
	flag.Parse()

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

	if !equal(pass1, pass2) {
		zero(pass1)
		zero(pass2)
		fmt.Fprintln(os.Stderr, "passphrases do not match")
		os.Exit(1)
	}
	zero(pass2)

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		zero(pass1)
		fmt.Fprintln(os.Stderr, "failed to generate salt")
		os.Exit(1)
	}

	unwrap := argon2.IDKey(pass1, salt, argonIter, argonMem, argonPar, 32)
	zero(pass1)

	kekPlain := make([]byte, 32)
	if _, err := rand.Read(kekPlain); err != nil {
		zero(unwrap)
		fmt.Fprintln(os.Stderr, "failed to generate KEK")
		os.Exit(1)
	}

	block, err := aes.NewCipher(unwrap)
	zero(unwrap)
	if err != nil {
		zero(kekPlain)
		fmt.Fprintln(os.Stderr, "internal error")
		os.Exit(1)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zero(kekPlain)
		fmt.Fprintln(os.Stderr, "internal error")
		os.Exit(1)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		zero(kekPlain)
		fmt.Fprintln(os.Stderr, "failed to generate nonce")
		os.Exit(1)
	}

	// Seal returns ciphertext || tag (32 + 16 = 48 bytes)
	sealed := gcm.Seal(nil, nonce, kekPlain, nil)

	var buf [kekBinLen]byte
	off := 0
	binary.BigEndian.PutUint16(buf[off:], version1)
	off += 2
	copy(buf[off:], salt)
	off += 16
	binary.BigEndian.PutUint32(buf[off:], argonMem)
	off += 4
	binary.BigEndian.PutUint32(buf[off:], argonIter)
	off += 4
	buf[off] = argonPar
	off++
	copy(buf[off:], nonce)
	off += 12
	copy(buf[off:], sealed)
	_ = off // == 87

	if err := os.WriteFile(*out, buf[:], 0600); err != nil {
		zero(kekPlain)
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", *out, err)
		os.Exit(1)
	}

	kekHex := hex.EncodeToString(kekPlain)
	zero(kekPlain)

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println("WARNING: Record the KEK hex below and store it in a physically")
	fmt.Println("secure location (safe or sealed envelope). This is printed once.")
	fmt.Println("=================================================================")
	fmt.Printf("KEK: %s\n", kekHex)
	fmt.Println("=================================================================")
	fmt.Printf("kek.bin written to: %s\n", *out)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// equal is constant-time byte comparison to prevent timing side-channels.
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
