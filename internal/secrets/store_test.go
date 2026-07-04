package secrets

import (
	"encoding/binary"
	"testing"
)

const (
	testMemKB   = 64 * 1024
	testIters   = 1
	testThreads = uint8(1)
)

// buildTestBlob creates a valid secrets.bin blob using fast Argon2 params for testing.
func buildTestBlob(passphrase []byte, m map[string]string) ([]byte, error) {
	return Encrypt(m, passphrase, testMemKB, testIters, testThreads)
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

func TestNewStoreReadsParamsFromHeader(t *testing.T) {
	blob, err := buildTestBlob([]byte("pass"), map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(blob, []byte("pass"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Destroy()
	got := store.Get("k")
	defer zero(got)
	if string(got) != "v" {
		t.Fatalf("Get(k) = %q, want %q", got, "v")
	}
}

func TestNewStoreRejectsBadArgonParams(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(blob []byte)
	}{
		{"zero iters", func(b []byte) { binary.BigEndian.PutUint32(b[22:26], 0) }},
		{"zero threads", func(b []byte) { b[26] = 0 }},
		{"oversized memKB", func(b []byte) { binary.BigEndian.PutUint32(b[18:22], 0xFFFFFFFF) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := buildTestBlob([]byte("pass"), map[string]string{"k": "v"})
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(blob)
			if _, err := NewStore(blob, []byte("pass")); err == nil {
				t.Fatal("expected error for tampered Argon2 params")
			}
		})
	}
}

func TestNewStoreShortData(t *testing.T) {
	if _, err := NewStore([]byte("short"), []byte("pass")); err == nil {
		t.Fatal("expected error on short data")
	}
}

func TestParseSecretsRejectsMalformedPayload(t *testing.T) {
	payload := encodePayload(map[string]string{"a": "b"})

	if _, err := parseSecrets(payload[:len(payload)-1]); err == nil {
		t.Fatal("expected error on truncated payload")
	}
	if _, err := parseSecrets([]byte{0, 0}); err == nil {
		t.Fatal("expected error on payload shorter than count prefix")
	}
	if _, err := parseSecrets(append(payload, 0)); err == nil {
		t.Fatal("expected error on trailing garbage")
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
