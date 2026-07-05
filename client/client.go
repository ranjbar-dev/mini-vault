// Package client provides a mini-vault client: dial over mTLS, fetch
// secrets, and check server health, without hand-wiring gRPC/TLS.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "github.com/ranjbar-dev/mini-vault/proto/minivault/v1"
)

// Config holds the mTLS material and dial target for connecting to a
// mini-vault server.
type Config struct {
	Addr       string // "host:9000"
	ServerName string // TLS ServerName; must match the server cert's SAN/CN

	CACert     []byte // PEM
	ClientCert []byte // PEM
	ClientKey  []byte // PEM

	// DialOptions are appended after transport credentials, e.g. a custom
	// dialer for tests (grpc.WithContextDialer).
	DialOptions []grpc.DialOption
}

// Client is a mini-vault gRPC client.
type Client struct {
	conn *grpc.ClientConn
	rpc  pb.VaultServiceClient
}

// New dials a mini-vault server using in-memory PEM material.
func New(cfg Config) (*Client, error) {
	cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(cfg.CACert) {
		return nil, errors.New("failed to parse CA cert")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
	})

	opts := append([]grpc.DialOption{grpc.WithTransportCredentials(creds)}, cfg.DialOptions...)
	conn, err := grpc.NewClient(cfg.Addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	return &Client{conn: conn, rpc: pb.NewVaultServiceClient(conn)}, nil
}

// NewFromFiles reads PEM material from disk and dials, per the layout
// produced by the "First-time setup" steps in README.md.
func NewFromFiles(addr, serverName, caCertPath, clientCertPath, clientKeyPath string) (*Client, error) {
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	clientCert, err := os.ReadFile(clientCertPath)
	if err != nil {
		return nil, fmt.Errorf("read client cert: %w", err)
	}
	clientKey, err := os.ReadFile(clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read client key: %w", err)
	}

	return New(Config{
		Addr:       addr,
		ServerName: serverName,
		CACert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
	})
}

// GetSecret fetches a secret's raw bytes by name. Zero the returned slice
// after use.
func (c *Client) GetSecret(ctx context.Context, name string) ([]byte, error) {
	resp, err := c.rpc.GetSecret(ctx, &pb.GetSecretRequest{Name: name})
	if err != nil {
		return nil, err
	}
	return resp.Value, nil
}

// GetSecretString fetches a secret and returns it as a string. Because Go
// strings are immutable, the returned value cannot be zeroed; prefer
// GetSecret for highly sensitive values.
func (c *Client) GetSecretString(ctx context.Context, name string) (string, error) {
	val, err := c.GetSecret(ctx, name)
	if err != nil {
		return "", err
	}
	defer Zero(val)
	return string(val), nil
}

// HealthCheck reports whether the vault has secrets loaded and how many.
func (c *Client) HealthCheck(ctx context.Context) (loaded bool, count int, err error) {
	resp, err := c.rpc.HealthCheck(ctx, &pb.HealthCheckRequest{})
	if err != nil {
		return false, 0, err
	}
	return resp.Loaded, int(resp.Count), nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Zero overwrites b with zeroes; call after using a secret value.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// IsNotFound reports whether err is the "secret not found" error.
func IsNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// IsPermissionDenied reports whether err is an auth failure (bad or missing
// client certificate CN).
func IsPermissionDenied(err error) bool {
	return status.Code(err) == codes.PermissionDenied
}

// IsRateLimited reports whether err is a rate-limit rejection.
func IsRateLimited(err error) bool {
	return status.Code(err) == codes.ResourceExhausted
}
