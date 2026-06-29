package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port         string
	ClientCN     string
	KEKVersion   string
	RateLimitRPM int
	LogLevel     string
}

func Load() Config {
	rpm, _ := strconv.Atoi(getenv("VAULT_RATE_LIMIT_RPM", "5"))
	if rpm <= 0 {
		rpm = 5
	}
	return Config{
		Port:         getenv("VAULT_PORT", "9000"),
		ClientCN:     getenv("VAULT_CLIENT_CN", "wallet-signer"),
		KEKVersion:   getenv("VAULT_KEK_VERSION", "v1"),
		RateLimitRPM: rpm,
		LogLevel:     getenv("VAULT_LOG_LEVEL", "info"),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
