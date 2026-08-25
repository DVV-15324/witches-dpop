package dpop

import (
	"errors"
	"time"

	"github.com/gin-gonic/gin"
)

func DPoPVerify(c *gin.Context, proof string, jkt string, clockSkew time.Duration, accessToken string) error {

	// 1. Trích xuất JKT từ access token (stateless)
	jkt, err := ExtractJKTFromToken(accessToken)
	if err != nil {
		return errors.New("invalid access token: " + err.Error())
	}

	// 2. Verify proof
	opts := VerifyOptions{
		Proof:       proof,
		AccessToken: accessToken,
		Method:      c.Request.Method,
		URI:         c.Request.URL.String(),
		ExpectedJKT: jkt,
		ClockSkew:   clockSkew,
	}
	// PublicKey ở đây sẽ được dùng bên trong verify (nếu parse token)
	// Nhưng VerifyOptions hiện tại không có PublicKey, vì hàm VerifyProof đã tự lấy từ jwk header.
	// Do đó ta không cần truyền PublicKey vào VerifyProof nữa.
	_, err = VerifyProof(opts)
	if err != nil {
		return errors.New("invalid DPoP proof: " + err.Error())
	}
	return nil
}
