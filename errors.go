package dpop

import "errors"

var (
	ErrInvalidProof     = errors.New("invalid DPoP proof")
	ErrInvalidProofAlg  = errors.New("invalid algorithm (must be ES256)")
	ErrInvalidProofType = errors.New("invalid typ (must be dpop+jwt)")
	ErrMissingJWK       = errors.New("missing jwk header")
	ErrInvalidHTM       = errors.New("invalid HTTP method (htm)")
	ErrInvalidHTU       = errors.New("invalid HTTP URI (htu)")
	ErrProofNotYetValid = errors.New("proof issued in the future")
	ErrProofExpired     = errors.New("proof expired (too old)")
	ErrInvalidATH       = errors.New("access token hash mismatch")
	ErrJKTMismatch      = errors.New("JKT mismatch")
	ErrInvalidJWT       = errors.New("invalid JWT format")
	ErrMissingCNF       = errors.New("cnf claim missing in access token")
	ErrMissingJKTInCNF  = errors.New("jkt missing in cnf claim")
)
