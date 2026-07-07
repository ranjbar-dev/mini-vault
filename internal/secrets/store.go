package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	secretsBinVersion = uint16(0x0003)
	headerLen         = 39 // 2+16+4+4+1+12

	// Bounds for Argon2id params read from the blob header. A corrupted or
	// tampered header must not get to choose our memory allocation — argon2
	// runs before the GCM tag can be verified.
	maxArgonMemKB   = uint32(4 * 1024 * 1024) // 4 GB
	maxArgonIters   = uint32(100)
	maxArgonThreads = uint8(64)
)

var errInvalid = errors.New("invalid secrets file")

// Store holds decrypted secret values in memory.
// All methods are safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	secrets map[string]*memguard.LockedBuffer
	loaded  bool
}

// NewStore decrypts a secrets.bin blob using passphrase and loads the secrets.
// Argon2id parameters are read from the blob header.
// passphrase is zeroed before returning.
func NewStore(data []byte, passphrase []byte) (*Store, error) {
	if len(data) < headerLen {
		zero(passphrase)
		return nil, errInvalid
	}
	memKB := binary.BigEndian.Uint32(data[18:22])
	iters := binary.BigEndian.Uint32(data[22:26])
	threads := data[26]
	if memKB == 0 || memKB > maxArgonMemKB ||
		iters == 0 || iters > maxArgonIters ||
		threads == 0 || threads > maxArgonThreads {
		zero(passphrase)
		return nil, errInvalid
	}
	return newStore(data, passphrase, memKB, iters, threads)
}

// newStore is the internal constructor. memKB, iters, threads are used for
// Argon2id key derivation; they must match the values used during encryption.
// Tests call this directly with fast params; NewStore reads params from the blob.
func newStore(data []byte, passphrase []byte, memKB uint32, iters uint32, threads uint8) (*Store, error) {
	defer zero(passphrase)

	if len(data) < headerLen {
		return nil, errInvalid
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

	m, err := parseSecrets(plaintext)
	if err != nil {
		return nil, errors.New("failed to initialise vault")
	}

	return &Store{secrets: m, loaded: true}, nil
}

// Encrypt builds a secrets.bin blob: it derives a key from passphrase via
// Argon2id with the given params and seals the encoded secrets with
// AES-256-GCM under a fresh salt and nonce. Inverse of NewStore.
// The caller retains ownership of passphrase and must zero it.
func Encrypt(m map[string]string, passphrase []byte, memKB, iters uint32, threads uint8) ([]byte, error) {
	for k := range m {
		if len(k) == 0 || len(k) > 65535 {
			return nil, errors.New("secret name length must be 1–65535 bytes")
		}
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	key := argon2.IDKey(passphrase, salt, iters, memKB, threads, 32)
	block, err := aes.NewCipher(key)
	zero(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	payload := encodePayload(m)
	sealed := gcm.Seal(nil, nonce, payload, nil)
	zero(payload)

	hdr := make([]byte, headerLen, headerLen+len(sealed))
	binary.BigEndian.PutUint16(hdr[0:], secretsBinVersion)
	copy(hdr[2:], salt)
	binary.BigEndian.PutUint32(hdr[18:], memKB)
	binary.BigEndian.PutUint32(hdr[22:], iters)
	hdr[26] = threads
	copy(hdr[27:], nonce)
	return append(hdr, sealed...), nil
}

// encodePayload serializes secrets as a length-prefixed binary payload:
// [uint32 count] then per secret [uint16 nameLen][name][uint32 valLen][value].
// Binary instead of JSON so decoding never creates secret values as Go
// strings, which cannot be zeroed.
func encodePayload(m map[string]string) []byte {
	size := 4
	for k, v := range m {
		size += 2 + len(k) + 4 + len(v)
	}
	buf := make([]byte, 0, size)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(m)))
	for k, v := range m {
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(k)))
		buf = append(buf, k...)
		buf = binary.BigEndian.AppendUint32(buf, uint32(len(v)))
		buf = append(buf, v...)
	}
	return buf
}

// parseSecrets decodes an encodePayload payload. Each value is copied into a
// memguard.LockedBuffer (locked, non-swappable, zeroed on Destroy) so no
// plaintext secret value lives in ordinary GC-managed memory.
func parseSecrets(plaintext []byte) (map[string]*memguard.LockedBuffer, error) {
	if len(plaintext) < 4 {
		return nil, errInvalid
	}
	count := binary.BigEndian.Uint32(plaintext)
	off := 4
	m := make(map[string]*memguard.LockedBuffer, int(min(count, 1024)))
	fail := func() (map[string]*memguard.LockedBuffer, error) {
		for _, v := range m {
			v.Destroy()
		}
		return nil, errInvalid
	}
	for range count {
		if off+2 > len(plaintext) {
			return fail()
		}
		nameLen := int(binary.BigEndian.Uint16(plaintext[off:]))
		off += 2
		if nameLen == 0 || off+nameLen > len(plaintext) {
			return fail()
		}
		name := string(plaintext[off : off+nameLen])
		off += nameLen
		if off+4 > len(plaintext) {
			return fail()
		}
		valLen := int(binary.BigEndian.Uint32(plaintext[off:]))
		off += 4
		if off+valLen > len(plaintext) {
			return fail()
		}
		buf := memguard.NewBufferFromBytes(plaintext[off : off+valLen])
		m[name] = buf
		off += valLen
	}
	if off != len(plaintext) {
		return fail()
	}
	return m, nil
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
	dst := make([]byte, v.Size())
	copy(dst, v.Bytes())
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
		v.Destroy()
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
