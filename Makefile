.PHONY: proto build encrypt gentest lint test

PROTO_DIR := proto/minivault/v1

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       $(PROTO_DIR)/vault.proto

build:
	go build -ldflags="-s -w" -o bin/mini-vault      ./cmd/mini-vault
	go build -ldflags="-s -w" -o bin/vault-encrypt   ./cmd/vault-encrypt

encrypt:
	go run ./cmd/vault-encrypt

gentest:
	go run ./cmd/gentest-secrets

lint:
	golangci-lint run

test:
	go test -race ./...
