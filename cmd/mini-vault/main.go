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
	"github.com/yourorg/mini-vault/internal/kek"
	"github.com/yourorg/mini-vault/internal/ratelimit"
	"github.com/yourorg/mini-vault/internal/server"
	pb "github.com/yourorg/mini-vault/proto/minivault/v1"
)

func main() {
	defer memguard.Purge()

	cfg := config.Load()
	setupLogger(cfg.LogLevel)

	passphrase, err := kek.ReadPassphrase()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to initialise vault")
		os.Exit(1)
	}

	store, err := kek.NewKekStore(minivault.WrappedKEK, passphrase)
	kek.ZeroBytes(passphrase)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	grpcSrv, err := server.New(minivault.CACert, minivault.ServerCert, minivault.ServerKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to initialise vault")
		os.Exit(1)
	}

	limiter := ratelimit.New(cfg.RateLimitRPM, 60*time.Second)
	handler := server.NewHandler(store, limiter, cfg.ClientCN, cfg.KEKVersion)
	pb.RegisterVaultServiceServer(grpcSrv, handler)

	lis, err := server.Listen(":" + cfg.Port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to initialise vault")
		os.Exit(1)
	}

	slog.Info("mini-vault ready", "kek_version", cfg.KEKVersion, "port", cfg.Port)

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
