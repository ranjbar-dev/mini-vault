package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// New builds a gRPC server with mTLS using the provided PEM-encoded cert material.
func New(caCert, serverCert, serverKey []byte) (*grpc.Server, error) {
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, errors.New("failed to parse CA certificate")
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	creds := credentials.NewTLS(tlsCfg)
	srv := grpc.NewServer(grpc.Creds(creds))
	return srv, nil
}

// Listen creates a TCP listener on addr (e.g. ":9000").
func Listen(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
