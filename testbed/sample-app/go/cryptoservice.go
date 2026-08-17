package main

import (
	"crypto/aes"
	"crypto/des"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
)

// BAD: MD5 digest
func fingerprint(data []byte) [16]byte {
	return md5.Sum(data)
}

// BAD: SHA-1
func legacyHash(data []byte) [20]byte {
	return sha1.Sum(data)
}

// OK: SHA-256
func strongHash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// BAD: DES cipher
func legacyCipher(key []byte) {
	block, _ := des.NewCipher(key)
	_ = block
}

// OK: AES cipher (size not statically known here)
func modernCipher(key []byte) {
	block, _ := aes.NewCipher(key)
	_ = block
}

// BAD: RSA-2048 key (quantum-broken)
func rsaKey() {
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
}

// BAD: ECDSA over P-256 (quantum-broken)
func ecdsaKey() {
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// BAD: DSA (quantum-broken)
func dsaParams() {
	var params dsa.Parameters
	_ = params
}

// BAD: TLS with min version 1.0 and legacy cipher suite
func legacyTLS() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		},
	}
}

// OK: TLS 1.3
func modernTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

var _ = x509.MarshalPKCS1PrivateKey
