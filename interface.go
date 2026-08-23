package dpop

type JwtService interface {
	GetJKTFromToken(tokenStr string) (string, error)
}
