package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/argon2"
)

const (
	testMemKB   = 64 * 1024
	testIters   = 1
	testThreads = uint8(1)
)

// buildTestBlob creates a valid secrets.bin blob using fast Argon2 params for testing.
func buildTestBlob(passphrase []byte, m map[string]string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := argon2.IDKey(passphrase, salt, testIters, testMemKB, testThreads, 32)
	defer zero(key)

	block, err := aes.NewCipher(key)
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

	plaintext, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	zero(plaintext)

	header := make([]byte, headerLen)
	off := 0
	binary.BigEndian.PutUint16(header[off:], secretsBinVersion)
	off += 2
	copy(header[off:], salt)
	off += 16
	binary.BigEndian.PutUint32(header[off:], testMemKB)
	off += 4
	binary.BigEndian.PutUint32(header[off:], testIters)
	off += 4
	header[off] = testThreads
	off++
	copy(header[off:], nonce)

	return append(header, sealed...), nil
}

func TestStoreRoundTrip(t *testing.T) {
	secrets := map[string]string{
		"kek":      "deadbeef",
		"password": "hunter2",
	}
	passphrase := []byte("test-passphrase")

	blob, err := buildTestBlob(passphrase, secrets)
	if err != nil {
		t.Fatal(err)
	}

	store, err := newStore(blob, []byte("test-passphrase"), testMemKB, testIters, testThreads)
	if err != nil {
		t.Fatalf("newStore: %v", err)
	}
	defer store.Destroy()

	if !store.Loaded() {
		t.Fatal("expected Loaded() == true")
	}
	if store.Count() != 2 {
		t.Fatalf("expected Count() == 2, got %d", store.Count())
	}

	got := store.Get("kek")
	if got == nil {
		t.Fatal("Get(kek) returned nil")
	}
	defer zero(got)
	if string(got) != "deadbeef" {
		t.Fatalf("Get(kek) = %q, want %q", got, "deadbeef")
	}
}

func TestStoreGetNotFound(t *testing.T) {
	blob, err := buildTestBlob([]byte("pass"), map[string]string{"a": "b"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(blob, []byte("pass"), testMemKB, testIters, testThreads)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Destroy()
	if got := store.Get("nonexistent"); got != nil {
		t.Fatalf("expected nil for nonexistent key, got %q", got)
	}
}

func TestStoreWrongPassphrase(t *testing.T) {
	blob, err := buildTestBlob([]byte("correct"), map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = newStore(blob, []byte("wrong"), testMemKB, testIters, testThreads)
	if err == nil {
		t.Fatal("expected error on wrong passphrase")
	}
}

func TestStoreBadData(t *testing.T) {
	_, err := newStore([]byte("short"), []byte("pass"), testMemKB, testIters, testThreads)
	if err == nil {
		t.Fatal("expected error on bad data")
	}
}

func TestStoreDestroyIdempotent(t *testing.T) {
	blob, err := buildTestBlob([]byte("pass"), map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(blob, []byte("pass"), testMemKB, testIters, testThreads)
	if err != nil {
		t.Fatal(err)
	}
	store.Destroy()
	store.Destroy() // must not panic
}

func TestStoreGetReturnsCopy(t *testing.T) {
	blob, err := buildTestBlob([]byte("pass"), map[string]string{"key": "value"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(blob, []byte("pass"), testMemKB, testIters, testThreads)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Destroy()

	got1 := store.Get("key")
	got2 := store.Get("key")
	defer zero(got1)
	defer zero(got2)
	if len(got1) == 0 || len(got2) == 0 {
		t.Fatal("Get should return non-empty slices")
	}
	if &got1[0] == &got2[0] {
		t.Fatal("Get should return independent copies")
	}
}

func TestStoreCount(t *testing.T) {
	blob, err := buildTestBlob([]byte("pass"), map[string]string{"a": "1", "b": "2", "c": "3"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(blob, []byte("pass"), testMemKB, testIters, testThreads)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Destroy()
	if store.Count() != 3 {
		t.Fatalf("expected Count() == 3, got %d", store.Count())
	}
}
