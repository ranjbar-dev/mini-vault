package kek

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

const (
	kekBinLen = 87
	version1  = uint16(0x0001)
)

// KekStore holds the plaintext KEK in a memguard-protected buffer.
type KekStore struct {
	buf    *memguard.LockedBuffer
	loaded bool
}

// NewKekStore parses wrapped, derives the unwrapping key from passphrase,
// decrypts the KEK, and loads it into a locked buffer.
// passphrase is zeroed before returning.
func NewKekStore(wrapped []byte, passphrase []byte) (*KekStore, error) {
	defer zero(passphrase)

	if len(wrapped) != kekBinLen {
		return nil, errors.New("invalid key file")
	}

	off := 0
	ver := binary.BigEndian.Uint16(wrapped[off : off+2])
	off += 2
	if ver != version1 {
		return nil, errors.New("invalid key file")
	}

	salt := wrapped[off : off+16]
	off += 16
	memKB := binary.BigEndian.Uint32(wrapped[off : off+4])
	off += 4
	iters := binary.BigEndian.Uint32(wrapped[off : off+4])
	off += 4
	threads := wrapped[off]
	off++
	nonce := wrapped[off : off+12]
	off += 12
	// ciphertext (32 bytes) || tag (16 bytes) as produced by GCM Seal
	ciphertextAndTag := wrapped[off : off+48]

	unwrap := argon2.IDKey(passphrase, salt, iters, memKB, threads, 32)
	defer zero(unwrap)

	block, err := aes.NewCipher(unwrap)
	if err != nil {
		return nil, errors.New("failed to initialise vault")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to initialise vault")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		// ponytail: AES-GCM tag mismatch == wrong passphrase; keep message generic
		return nil, errors.New("failed to initialise vault")
	}
	defer zero(plaintext)

	buf := memguard.NewBufferFromBytes(plaintext)
	return &KekStore{buf: buf, loaded: true}, nil
}

// Get returns a copy of the KEK bytes. The caller must zero the returned slice after use.
func (s *KekStore) Get() []byte {
	src := s.buf.Bytes()
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// IsLoaded reports whether the KEK is held in memory.
func (s *KekStore) IsLoaded() bool {
	return s.loaded
}

// Destroy wipes the KEK buffer.
func (s *KekStore) Destroy() {
	s.loaded = false
	s.buf.Destroy()
}

// ZeroBytes wipes a byte slice in place.
func ZeroBytes(b []byte) { zero(b) }

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
