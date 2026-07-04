package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/awnumar/memguard"
	minivault "github.com/yourorg/mini-vault"
	"github.com/yourorg/mini-vault/internal/config"
	"github.com/yourorg/mini-vault/internal/ratelimit"
	"github.com/yourorg/mini-vault/internal/secrets"
	"github.com/yourorg/mini-vault/internal/server"
	pb "github.com/yourorg/mini-vault/proto/minivault/v1"
)

func main() {
	defer memguard.Purge()

	cfg := config.Load()
	setupLogger(cfg.LogLevel)

	var passphrase []byte
	if p := os.Getenv("VAULT_PASSPHRASE"); p != "" {
		passphrase = []byte(p)
	} else {
		fmt.Fprint(os.Stderr, "Enter passphrase: ")
		var err error
		passphrase, err = secrets.ReadPassphrase()
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to initialise vault")
			os.Exit(1)
		}
	}

	store, err := secrets.NewStore(minivault.EncryptedSecrets, passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// Cert and listener errors carry no secret material — print them as-is.
	// Only the passphrase/decrypt path above stays generic.
	grpcSrv, err := server.New(minivault.CACert, minivault.ServerCert, minivault.ServerKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls setup: %v\n", err)
		os.Exit(1)
	}

	limiter := ratelimit.New(cfg.RateLimitRPM, 60*time.Second)
	handler := server.NewHandler(store, limiter, cfg.ClientCN)
	pb.RegisterVaultServiceServer(grpcSrv, handler)

	lis, err := server.Listen(":" + cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}

	slog.Info("mini-vault ready", "secrets_count", store.Count(), "port", cfg.Port)

	go func() {
		if err := grpcSrv.Serve(lis); err != nil {
			slog.Error("serve error", "err", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	grpcSrv.GracefulStop()
	store.Destroy()
	memguard.Purge()
}

func setupLogger(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}
