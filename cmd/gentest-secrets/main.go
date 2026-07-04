// gentest-secrets: generates a test data/secrets.bin for local dev/CI only.
// NOT for production — the passphrase and secret values are hardcoded and public.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/yourorg/mini-vault/internal/secrets"
)

const testPassphrase = "test-passphrase-change-before-production"

func main() {
	fmt.Fprintln(os.Stderr, "WARNING: This generates TEST-ONLY secrets. Do NOT use in production.")

	m := map[string]string{
		"kek":         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"db_password": "hunter2",
		"api_key":     "sk-test-abc123",
	}

	// Write data/secrets.json (for reference; gitignored)
	jsonBytes, err := json.MarshalIndent(m, "", "  ")
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

	blob, err := secrets.Encrypt(m, []byte(testPassphrase), 262144, 3, 2)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := os.WriteFile("data/secrets.bin", blob, 0600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Println("data/secrets.bin written (TEST ONLY — regenerate with vault-encrypt before production)")
	fmt.Printf("Test passphrase: %s\n", testPassphrase)
}
