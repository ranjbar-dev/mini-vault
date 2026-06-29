package minivault

import _ "embed"

//go:embed keys/kek.bin
var WrappedKEK []byte

//go:embed keys/ca.crt
var CACert []byte

//go:embed keys/server.crt
var ServerCert []byte

//go:embed keys/server.key
var ServerKey []byte
