package dpop

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type PublicKeyStore interface {
	GetByJKT(jkt string) (interface{}, error)
}

func DPoPVerify(c *gin.Context, proof string, keyStore PublicKeyStore, clockSkew time.Duration, accessToken string) {

	// 1. Trích xuất JKT từ access token (stateless)
	jkt, err := ExtractJKTFromToken(accessToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid access token: " + err.Error()})
		return
	}

	// 2. Lấy public key từ store (DB/Redis) theo JKT
	pubKey, err := keyStore.GetByJKT(jkt)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "public key not found"})
		return
	}

	// 3. Verify proof
	opts := VerifyOptions{
		Proof:       proof,
		AccessToken: accessToken,
		Method:      c.Request.Method,
		URI:         c.Request.URL.String(),
		PublicKey:   pubKey,
		ExpectedJKT: jkt,
		ClockSkew:   clockSkew,
	}
	// PublicKey ở đây sẽ được dùng bên trong verify (nếu parse token)
	// Nhưng VerifyOptions hiện tại không có PublicKey, vì hàm VerifyProof đã tự lấy từ jwk header.
	// Do đó ta không cần truyền PublicKey vào VerifyProof nữa.
	_, err = VerifyProof(opts)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid DPoP proof: " + err.Error()})
		return
	}

}
