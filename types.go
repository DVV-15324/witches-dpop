package dpop

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWK represents a JSON Web Key for EC P-256
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// DPoPClaims are the claims inside a DPoP proof JWT
type DPoPClaims struct {
	HTU string `json:"htu"`           // HTTP URI
	HTM string `json:"htm"`           // HTTP Method
	ATH string `json:"ath,omitempty"` // Access Token Hash (SHA-256, base64url)
	jwt.RegisteredClaims
}

// DPoPHeader is the JWT header with optional JWK
type DPoPHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	JWK *JWK   `json:"jwk,omitempty"`
}

// ProofOptions for creating a proof
type ProofOptions struct {
	Method      string // HTTP method (GET, POST, ...)
	URI         string // Full request URI
	AccessToken string // Optional: access token to bind
	JTI         string // Optional: custom jti (auto-generated if empty)
}

// VerifyOptions for verifying a proof
type VerifyOptions struct {
	Proof       string        // DPoP proof JWT
	AccessToken string        // Access token (for ath & cnf.jkt binding)
	Method      string        // Expected HTTP method
	URI         string        // Expected URI
	ExpectedJKT string        // JKT từ access token (cnf.jkt)
	PublicKey   interface{}   // *ecdsa.PublicKey (lấy từ DB theo jkt)
	ClockSkew   time.Duration // Allowed clock skew (default 5s)
}

// VerifyProofResult trả về claims và JKT đã verify
type VerifyProofResult struct {
	Claims *DPoPClaims
	JKT    string // JKT từ proof (cũng là expectedJKT)
}
