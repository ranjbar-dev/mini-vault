package kek

import (
	"golang.org/x/term"
	"os"
)

// ReadPassphrase reads a passphrase from stdin without echo.
// The caller must zero the returned slice after use.
func ReadPassphrase() ([]byte, error) {
	return term.ReadPassword(int(os.Stdin.Fd()))
}
