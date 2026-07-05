package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/ranjbar-dev/mini-vault/internal/ratelimit"
	"github.com/ranjbar-dev/mini-vault/internal/secrets"
	"github.com/ranjbar-dev/mini-vault/internal/server"
	pb "github.com/ranjbar-dev/mini-vault/proto/minivault/v1"
)

const testServerName = "mini-vault-test"

// genCert issues a leaf cert signed by caKey/caCert. If dnsName is set the
// cert is usable as a server cert (SAN required, Go rejects CN-only certs).
func genCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, cn, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	if dnsName != "" {
		tmpl.DNSNames = []string{dnsName}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// genCA generates a self-signed CA cert/key and returns both the PEM and
// the parsed values needed to sign leaf certs.
func genCA(t *testing.T) (caPEM []byte, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return caPEM, caCert, caKey
}

// testServer bundles the pieces needed to dial a bufconn-hosted mTLS
// VaultService and to mint additional client certs signed by its CA.
type testServer struct {
	dialer     func(context.Context, string) (net.Conn, error)
	caPEM      []byte
	caCert     *x509.Certificate
	caKey      *ecdsa.PrivateKey
	clientCert []byte
	clientKey  []byte
}

// startTestServer builds a real mTLS VaultService, serves it over bufconn,
// and returns everything needed to connect with a client cert whose CN
// matches allowedCN.
func startTestServer(t *testing.T, secretsMap map[string]string, allowedCN string) *testServer {
	t.Helper()

	caPEM, caCert, caKey := genCA(t)
	serverCertPEM, serverKeyPEM := genCert(t, caCert, caKey, "server", testServerName)
	clientCertPEM, clientKeyPEM := genCert(t, caCert, caKey, allowedCN, "")

	blob, err := secrets.Encrypt(secretsMap, []byte("test-passphrase"), 64*1024, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := secrets.NewStore(blob, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Destroy)

	grpcSrv, err := server.New(caPEM, serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.NewHandler(store, ratelimit.New(1000, time.Minute), allowedCN)
	pb.RegisterVaultServiceServer(grpcSrv, handler)

	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)

	return &testServer{
		dialer: func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		},
		caPEM:      caPEM,
		caCert:     caCert,
		caKey:      caKey,
		clientCert: clientCertPEM,
		clientKey:  clientKeyPEM,
	}
}

func TestClientGetSecretAndHealthCheck(t *testing.T) {
	ts := startTestServer(t, map[string]string{
		"db_password": "hunter2",
	}, "vault-client")

	c, err := New(Config{
		Addr:        "passthrough:///bufnet",
		ServerName:  testServerName,
		CACert:      ts.caPEM,
		ClientCert:  ts.clientCert,
		ClientKey:   ts.clientKey,
		DialOptions: []grpc.DialOption{grpc.WithContextDialer(ts.dialer)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	ctx := context.Background()

	val, err := c.GetSecretString(ctx, "db_password")
	if err != nil {
		t.Fatalf("GetSecretString: %v", err)
	}
	if val != "hunter2" {
		t.Fatalf("GetSecretString = %q, want %q", val, "hunter2")
	}

	if _, err := c.GetSecret(ctx, "nonexistent"); !IsNotFound(err) {
		t.Fatalf("GetSecret(nonexistent) err = %v, want NotFound", err)
	}

	loaded, count, err := c.HealthCheck(ctx)
	if err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
	if !loaded || count != 1 {
		t.Fatalf("HealthCheck = (loaded=%v, count=%d), want (true, 1)", loaded, count)
	}
}

func TestClientWrongCNIsPermissionDenied(t *testing.T) {
	ts := startTestServer(t, map[string]string{"k": "v"}, "vault-client")

	// A cert signed by the same CA but with a CN the server doesn't allow.
	wrongCertPEM, wrongKeyPEM := genCert(t, ts.caCert, ts.caKey, "wrong-client", "")

	c, err := New(Config{
		Addr:        "passthrough:///bufnet",
		ServerName:  testServerName,
		CACert:      ts.caPEM,
		ClientCert:  wrongCertPEM,
		ClientKey:   wrongKeyPEM,
		DialOptions: []grpc.DialOption{grpc.WithContextDialer(ts.dialer)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	if _, err := c.GetSecret(context.Background(), "k"); !IsPermissionDenied(err) {
		t.Fatalf("expected PermissionDenied for mismatched CN, got %v", err)
	}
}
