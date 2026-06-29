package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	secretsBinVersion = uint16(0x0002)
	headerLen         = 39 // 2+16+4+4+1+12
)

// Store holds decrypted secret values in memory.
// All methods are safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	secrets map[string][]byte
	loaded  bool
}

// NewStore decrypts a secrets.bin blob using passphrase and loads the secrets.
// Argon2id parameters are read from the blob header.
// passphrase is zeroed before returning.
func NewStore(data []byte, passphrase []byte) (*Store, error) {
	if len(data) < headerLen {
		return newStore(data, passphrase, 0, 0, 0)
	}
	memKB := binary.BigEndian.Uint32(data[18:22])
	iters := binary.BigEndian.Uint32(data[22:26])
	threads := data[26]
	return newStore(data, passphrase, memKB, iters, threads)
}

// newStore is the internal constructor. memKB, iters, threads are used for
// Argon2id key derivation; they must match the values used during encryption.
// Tests call this directly with fast params; NewStore reads params from the blob.
func newStore(data []byte, passphrase []byte, memKB uint32, iters uint32, threads uint8) (*Store, error) {
	defer zero(passphrase)

	if len(data) < headerLen {
		return nil, errors.New("invalid secrets file")
	}

	off := 0
	ver := binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	if ver != secretsBinVersion {
		return nil, errors.New("invalid secrets file: wrong version")
	}

	salt := data[off : off+16]
	off += 16
	off += 9 // skip embedded memKB(4) + iters(4) + threads(1) — already read by NewStore
	nonce := data[off : off+12]
	off += 12
	ciphertextAndTag := data[off:]

	unwrapBuf := memguard.NewBufferFromBytes(argon2.IDKey(passphrase, salt, iters, memKB, threads, 32))
	defer unwrapBuf.Destroy()

	block, err := aes.NewCipher(unwrapBuf.Bytes())
	if err != nil {
		return nil, errors.New("failed to initialise vault")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("failed to initialise vault")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		// AES-GCM tag mismatch == wrong passphrase; keep message generic
		return nil, errors.New("failed to initialise vault")
	}
	defer zero(plaintext)

	var raw map[string]string
	if err := json.Unmarshal(plaintext, &raw); err != nil {
		return nil, errors.New("failed to initialise vault")
	}

	m := make(map[string][]byte, len(raw))
	for k, v := range raw {
		b := make([]byte, len(v))
		copy(b, v)
		m[k] = b
	}

	return &Store{secrets: m, loaded: true}, nil
}

// Get returns a copy of the named secret value.
// Returns nil if not found. The caller must zero the returned slice after use.
func (s *Store) Get(name string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[name]
	if !ok {
		return nil
	}
	dst := make([]byte, len(v))
	copy(dst, v)
	return dst
}

// Loaded reports whether secrets are held in memory.
func (s *Store) Loaded() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loaded
}

// Count returns the number of secrets currently loaded.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.secrets)
}

// Destroy zeros all secret values in the map. Safe to call more than once.
func (s *Store) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return
	}
	s.loaded = false
	for k, v := range s.secrets {
		zero(v)
		delete(s.secrets, k)
	}
}

// ReadPassphrase reads a passphrase from stdin without echo.
// The caller must zero the returned slice after use.
func ReadPassphrase() ([]byte, error) {
	return term.ReadPassword(int(os.Stdin.Fd()))
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
