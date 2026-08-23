package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func CreateProof(privateKey *ecdsa.PrivateKey, opts ProofOptions) (string, error) {
	if privateKey == nil {
		return "", errors.New("private key is nil")
	}
	if opts.Method == "" || opts.URI == "" {
		return "", errors.New("method and URI are required")
	}

	now := time.Now()
	jti := opts.JTI
	if jti == "" {
		jti = uuid.New().String()
	}

	claims := DPoPClaims{
		HTU: opts.URI,
		HTM: opts.Method,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
	}

	if opts.AccessToken != "" {
		hash := sha256.Sum256([]byte(opts.AccessToken))
		claims.ATH = base64.RawURLEncoding.EncodeToString(hash[:])
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt" // theo spec

	jwk, err := PublicKeyToJWK(&privateKey.PublicKey)
	if err != nil {
		return "", err
	}
	token.Header["jwk"] = jwk

	return token.SignedString(privateKey)
}
