package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// GenerateECDSAKey tạo cặp khoá ECDSA P-256
func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// PublicKeyToJWK chuyển ECDSA public key sang JWK
func PublicKeyToJWK(pub *ecdsa.PublicKey) (*JWK, error) {
	x := pad32(pub.X.Bytes())
	y := pad32(pub.Y.Bytes())
	return &JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(x),
		Y:   base64.RawURLEncoding.EncodeToString(y),
	}, nil
}

// JWKToPublicKey chuyển JWK về ECDSA public key
func JWKToPublicKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, errors.New("unsupported key type (must be EC P-256)")
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

// JWKThumbprint tính JWK thumbprint (RFC 7638)
func JWKThumbprint(jwk *JWK) (string, error) {
	// Sắp xếp key theo alphabet: crv, kty, x, y
	m := map[string]string{
		"crv": jwk.Crv,
		"kty": jwk.Kty,
		"x":   jwk.X,
		"y":   jwk.Y,
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// pad32 đảm bảo byte slice có độ dài 32 (cho P-256)
func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	pad := make([]byte, 32-len(b))
	return append(pad, b...)
}
