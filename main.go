package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"
)

func main() {
	// 1. FE tạo key pair
	fmt.Println("Generating ECDSA key pair...")
	privKey, err := GenerateECDSAKey()
	if err != nil {
		log.Fatal("Generate key error:", err)
	}
	pubKey := &privKey.PublicKey

	// 2. FE chuyển public key sang JWK
	jwk, err := PublicKeyToJWK(pubKey)
	if err != nil {
		log.Fatal("PublicKeyToJWK error:", err)
	}

	// 2.1 BE tính thumbprint (jkt)
	jkt, err := JWKThumbprint(jwk)
	if err != nil {
		log.Fatal("JWKThumbprint error:", err)
	}
	fmt.Printf("   JKT: %s\n\n", jkt)

	// 3. BE tạo access token (mock) với cnf.jkt
	accessToken := createMockAccessToken(jkt)
	fmt.Printf("Access Token (mock): %s\n\n", accessToken)

	// 4. FE tạo DPoP proof cho request
	method := "GET"
	uri := "https://api.example.com/resource"
	fmt.Printf("Preparing request: %s %s\n", method, uri)

	proof, err := CreateProof(privKey, ProofOptions{
		Method:      method,
		URI:         uri,
		AccessToken: accessToken,
	})
	if err != nil {
		log.Fatal("CreateProof error:", err)
	}
	fmt.Printf("Proof JWT: %s\n\n", proof)

	// 5. BE verify proof
	fmt.Println("Verifying proof on server...")
	opts := VerifyOptions{
		Proof:       proof,
		AccessToken: accessToken,
		Method:      method,
		URI:         uri,
		ExpectedJKT: jkt,
		ClockSkew:   5 * time.Second,
	}
	result, err := VerifyProof(opts)
	if err != nil {
		log.Fatal("VerifyProof error:", err)
	}
	fmt.Printf("Verification successful!\n")
	fmt.Printf("Claims: HTM=%s, HTU=%s, ATH=%s, JTI=%s\n",
		result.Claims.HTM,
		result.Claims.HTU,
		result.Claims.ATH,
		result.Claims.ID,
	)
}

// createMockAccessToken tạo access token giả có cnf.jkt (dùng alg=none)
func createMockAccessToken(jkt string) string {
	// Header: {"alg":"none","typ":"JWT"}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))

	// Payload: {"cnf":{"jkt":"<jkt>"}}
	payloadMap := map[string]interface{}{
		"cnf": map[string]string{"jkt": jkt},
	}
	payloadBytes, _ := json.Marshal(payloadMap)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Signature rỗng (vì alg=none)
	return header + "." + payload + "."
}
