package minivault

import _ "embed"

//go:embed data/secrets.bin
var EncryptedSecrets []byte

//go:embed keys/ca.crt
var CACert []byte

//go:embed keys/server.crt
var ServerCert []byte

//go:embed keys/server.key
var ServerKey []byte
