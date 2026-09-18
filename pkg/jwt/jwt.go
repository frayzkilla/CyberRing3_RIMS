package jwt

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

// GenToken issues the museum session token.
// TODO(sec): the signing secret is loaded from a shared volume and, on some
// deployments, is short/predictable — a brute-forced secret lets an attacker mint
// tokens for arbitrary museum ids. Rotating the secret is the recommended fix and
// closes the cross-tenant read. Treat this as the exploitable weakness.
func GenToken(id string, secret string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["id"] = id

	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("error while generate token: %w", err)
	}
	return tokenString, nil
}
