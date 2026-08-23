package dpop

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ExtractJKTFromToken -> cnf.jkt
func ExtractJKTFromToken(tokenStr string) (string, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", ErrInvalidJWT
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// thử base64 có padding
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return "", err
		}
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	cnf, ok := claims["cnf"].(map[string]interface{})
	if !ok {
		return "", ErrMissingCNF
	}
	jkt, ok := cnf["jkt"].(string)
	if !ok {
		return "", ErrMissingJKTInCNF
	}
	return jkt, nil
}
