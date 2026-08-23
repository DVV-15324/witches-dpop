package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VerifyProof kiểm tra toàn bộ DPoP proof
func VerifyProof(opts VerifyOptions) (*VerifyProofResult, error) {
	if err := validateVerifyOptions(opts); err != nil {
		return nil, err
	}

	// 1. Parse JWT + verify chữ ký, lấy claims và JWK
	token, claims, jwk, err := parseAndVerifyProof(opts.Proof, opts.ClockSkew)
	if err != nil {
		return nil, err
	}
	_ = token // không dùng thêm

	// 2. Validate claims cơ bản
	if err := validateClaims(claims, opts.Method, opts.URI, opts.ClockSkew); err != nil {
		return nil, err
	}

	// 3. Validate ATH
	if err := validateATH(claims, opts.AccessToken); err != nil {
		return nil, err
	}

	// 4. Validate JKT
	if err := validateJKT(jwk, opts.ExpectedJKT); err != nil {
		return nil, err
	}

	return &VerifyProofResult{
		Claims: claims,
		JKT:    opts.ExpectedJKT,
	}, nil
}

// ===== Internal helpers =====

func validateVerifyOptions(opts VerifyOptions) error {
	if opts.Proof == "" {
		return ErrInvalidProof
	}
	if opts.Method == "" || opts.URI == "" {
		return fmt.Errorf("method and URI are required")
	}
	if opts.ExpectedJKT == "" {
		return fmt.Errorf("expected JKT is required")
	}
	if opts.ClockSkew == 0 {
		opts.ClockSkew = 5 * time.Second
	}
	return nil
}

func parseAndVerifyProof(tokenStr string, clockSkew time.Duration) (*jwt.Token, *DPoPClaims, *JWK, error) {
	var claims DPoPClaims

	token, err := jwt.ParseWithClaims(
		tokenStr,
		&claims,
		func(t *jwt.Token) (interface{}, error) {
			// alg
			if t.Method != jwt.SigningMethodES256 {
				return nil, ErrInvalidProofAlg
			}
			// typ
			typ, ok := t.Header["typ"].(string)
			if !ok || !strings.EqualFold(typ, "dpop+jwt") {
				return nil, ErrInvalidProofType
			}
			// jwk
			rawJWK, ok := t.Header["jwk"]
			if !ok {
				return nil, ErrMissingJWK
			}
			jwk, err := jwkFromRaw(rawJWK)
			if err != nil {
				return nil, err
			}
			pubKey, err := JWKToPublicKey(jwk)
			if err != nil {
				return nil, fmt.Errorf("invalid public key: %w", err)
			}
			return pubKey, nil
		},
		jwt.WithLeeway(clockSkew),
	)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if !token.Valid {
		return nil, nil, nil, ErrInvalidProof
	}

	// Lấy lại jwk từ header để trả về
	rawJWK, ok := token.Header["jwk"]
	if !ok {
		return nil, nil, nil, ErrMissingJWK
	}
	jwk, err := jwkFromRaw(rawJWK)
	if err != nil {
		return nil, nil, nil, err
	}

	return token, &claims, jwk, nil
}

func jwkFromRaw(raw interface{}) (*JWK, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, ErrInvalidProof
	}
	var jwk JWK
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, ErrInvalidProof
	}
	return &jwk, nil
}

func validateClaims(claims *DPoPClaims, method, uri string, clockSkew time.Duration) error {
	if !strings.EqualFold(claims.HTM, method) {
		return ErrInvalidHTM
	}
	if claims.HTU != uri {
		return ErrInvalidHTU
	}
	if claims.IssuedAt == nil {
		return ErrInvalidProof
	}
	now := time.Now()
	if claims.IssuedAt.Time.After(now.Add(clockSkew)) {
		return ErrProofNotYetValid
	}
	if claims.IssuedAt.Time.Before(now.Add(-clockSkew - 5*time.Minute)) {
		return ErrProofExpired
	}
	if claims.ID == "" {
		return ErrInvalidProof
	}
	return nil
}

func validateATH(claims *DPoPClaims, accessToken string) error {
	if accessToken == "" {
		// Nếu không có access token thì không yêu cầu ATH
		return nil
	}
	hash := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	if claims.ATH != expected {
		return ErrInvalidATH
	}
	return nil
}

func validateJKT(jwk *JWK, expectedJKT string) error {
	actual, err := JWKThumbprint(jwk)
	if err != nil {
		return fmt.Errorf("calculate JKT: %w", err)
	}
	if actual != expectedJKT {
		return ErrJKTMismatch
	}
	return nil
}
