package server

import (
	"context"
	"crypto/x509"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/ranjbar-dev/mini-vault/internal/ratelimit"
	"github.com/ranjbar-dev/mini-vault/internal/secrets"
	pb "github.com/ranjbar-dev/mini-vault/proto/minivault/v1"
)

// Handler implements pb.VaultServiceServer.
type Handler struct {
	pb.UnimplementedVaultServiceServer
	store     *secrets.Store
	limiter   *ratelimit.Limiter
	allowedCN string
}

func NewHandler(store *secrets.Store, limiter *ratelimit.Limiter, allowedCN string) *Handler {
	return &Handler{
		store:     store,
		limiter:   limiter,
		allowedCN: allowedCN,
	}
}

func (h *Handler) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	cn, err := h.authorize(ctx)
	if err != nil {
		return nil, err
	}

	if !h.limiter.Allow(cn) {
		slog.Warn("request_denied", "client_cn", cn, "reason", "rate_limit_exceeded")
		return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}

	val := h.store.Get(req.Name)
	if val == nil {
		// Do NOT log the requested name — avoids leaking which names exist
		slog.Warn("secret_not_found", "client_cn", cn)
		return nil, status.Error(codes.NotFound, "not found")
	}
	defer zeroBytes(val)

	resp := &pb.GetSecretResponse{
		Value: append([]byte(nil), val...),
		Name:  req.Name,
	}

	slog.Info("secret_served", "client_cn", cn, "name", req.Name)
	return resp, nil
}

func (h *Handler) HealthCheck(ctx context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	if _, err := h.authorize(ctx); err != nil {
		return nil, err
	}
	return &pb.HealthCheckResponse{
		Loaded: h.store.Loaded(),
		Count:  int32(h.store.Count()),
	}, nil
}

// authorize verifies the peer presented a client certificate with the
// allowed CN. Every RPC must pass this — including HealthCheck, so a
// CA-signed cert with the wrong CN cannot probe the vault.
func (h *Handler) authorize(ctx context.Context) (string, error) {
	cn, err := clientCN(ctx)
	if err != nil || cn != h.allowedCN {
		slog.Warn("request_denied", "client_cn", cn, "reason", "cert_cn_mismatch")
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return cn, nil
}

func clientCN(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", status.Error(codes.Unauthenticated, "no client cert")
	}
	return certCN(tlsInfo.State.PeerCertificates[0]), nil
}

func certCN(cert *x509.Certificate) string {
	return cert.Subject.CommonName
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
