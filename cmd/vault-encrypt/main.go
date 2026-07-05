// vault-encrypt: pre-build CLI that encrypts data/secrets.json → data/secrets.bin.
// Run on an offline workstation before building the mini-vault binary.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/ranjbar-dev/mini-vault/internal/secrets"
)

const (
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

	var m map[string]string
	if err := json.Unmarshal(jsonBytes, &m); err != nil {
		fmt.Fprintln(os.Stderr, "invalid JSON: must be a flat map[string]string")
		os.Exit(1)
	}
	if len(m) == 0 {
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

	blob, err := secrets.Encrypt(m, pass1, argonMem, argonIter, argonPar)
	zero(pass1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encrypt failed: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outPath, blob, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	fmt.Printf("Wrote %d bytes to %s\n", len(blob), *outPath)
	fmt.Printf("%s is safe to commit to your private repo (encrypted).\n", *outPath)
	fmt.Printf("DELETE the plaintext input now: %s\n", *inPath)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
