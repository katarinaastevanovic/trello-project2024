package utils

import (
	"fmt"
	"os"

	"github.com/dgrijalva/jwt-go"
)

// ekstrakcija username iz tokena
func ExtractManagerUsernameFromToken(tokenString string) (string, error) {
	secretKey := os.Getenv("JWT_SECRET")
	if secretKey == "" {
		return "", fmt.Errorf("JWT_SECRET is not set")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return "", fmt.Errorf("error parsing token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username, exists := claims["username"]
		if !exists {
			return "", fmt.Errorf("username claim not found in token")
		}

		return username.(string), nil
	}

	return "", fmt.Errorf("invalid token")
}
