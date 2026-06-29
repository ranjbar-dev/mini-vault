package kek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/argon2"
)

// buildKekBin creates a valid 87-byte kek.bin for testing.
func buildKekBin(passphrase, kekPlain []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	unwrap := argon2.IDKey(passphrase, salt, 1, 64*1024, 1, 32) // fast params for test
	defer zero(unwrap)

	block, err := aes.NewCipher(unwrap)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, kekPlain, nil)

	var buf [kekBinLen]byte
	off := 0
	binary.BigEndian.PutUint16(buf[off:], version1)
	off += 2
	copy(buf[off:], salt)
	off += 16
	binary.BigEndian.PutUint32(buf[off:], 64*1024) // 64 MB — fast for test
	off += 4
	binary.BigEndian.PutUint32(buf[off:], 1)
	off += 4
	buf[off] = 1
	off++
	copy(buf[off:], nonce)
	off += 12
	copy(buf[off:], sealed)
	return buf[:], nil
}

func TestKekStoreRoundTrip(t *testing.T) {
	passphrase := []byte("test-passphrase")
	kekPlain := make([]byte, 32)
	if _, err := rand.Read(kekPlain); err != nil {
		t.Fatal(err)
	}

	wrapped, err := buildKekBin(passphrase, kekPlain)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewKekStore(wrapped, []byte("test-passphrase"))
	if err != nil {
		t.Fatalf("NewKekStore: %v", err)
	}
	defer store.Destroy()

	got := store.Get()
	defer zero(got)

	if len(got) != 32 {
		t.Fatalf("expected 32-byte KEK, got %d", len(got))
	}
	for i, b := range got {
		if b != kekPlain[i] {
			t.Fatal("KEK mismatch")
		}
	}
}

func TestKekStoreWrongPassphrase(t *testing.T) {
	passphrase := []byte("correct")
	kekPlain := make([]byte, 32)
	rand.Read(kekPlain) //nolint:errcheck

	wrapped, err := buildKekBin(passphrase, kekPlain)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewKekStore(wrapped, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error on wrong passphrase")
	}
}

func TestKekStoreBadLength(t *testing.T) {
	_, err := NewKekStore([]byte("short"), []byte("pass"))
	if err == nil {
		t.Fatal("expected error on bad length")
	}
}
