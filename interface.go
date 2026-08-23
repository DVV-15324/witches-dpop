package main

type JwtService interface {
	GetJKTFromToken(tokenStr string) (string, error)
}
