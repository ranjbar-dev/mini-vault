package server

import (
	"context"
	"crypto/x509"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/yourorg/mini-vault/internal/kek"
	"github.com/yourorg/mini-vault/internal/ratelimit"
	pb "github.com/yourorg/mini-vault/proto/minivault/v1"
)

// Handler implements pb.VaultServiceServer.
type Handler struct {
	pb.UnimplementedVaultServiceServer
	store      *kek.KekStore
	limiter    *ratelimit.Limiter
	allowedCN  string
	kekVersion string
}

func NewHandler(store *kek.KekStore, limiter *ratelimit.Limiter, allowedCN, kekVersion string) *Handler {
	return &Handler{
		store:      store,
		limiter:    limiter,
		allowedCN:  allowedCN,
		kekVersion: kekVersion,
	}
}

func (h *Handler) GetKEK(ctx context.Context, req *pb.GetKEKRequest) (*pb.GetKEKResponse, error) {
	cn, err := clientCN(ctx)
	if err != nil || cn != h.allowedCN {
		slog.Warn("kek_denied", "client_cn", cn, "reason", "cert_cn_mismatch")
		return nil, status.Error(codes.PermissionDenied, "permission denied")
	}

	if !h.limiter.Allow(cn) {
		slog.Warn("kek_denied", "client_cn", cn, "reason", "rate_limit_exceeded")
		return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
	}

	if req.Version != h.kekVersion {
		return nil, status.Error(codes.InvalidArgument, "unknown version")
	}

	kekBytes := h.store.Get()
	defer kek.ZeroBytes(kekBytes)

	// copy into response (protobuf will hold it; we zero our local slice)
	resp := &pb.GetKEKResponse{
		Kek:     append([]byte(nil), kekBytes...),
		Version: h.kekVersion,
	}

	slog.Info("kek_served", "client_cn", cn, "version", h.kekVersion)
	return resp, nil
}

func (h *Handler) HealthCheck(_ context.Context, _ *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		KekLoaded: h.store.IsLoaded(),
		Version:   h.kekVersion,
	}, nil
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
