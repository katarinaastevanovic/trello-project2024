package utils

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Učitaj tajni ključ iz okruženja
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateToken(email, role string) (string, error) {
	claims := &Claims{
		Email: email,
		Role:  role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func GetEmailFromToken(tokenStr string) (string, error) {
	claims, err := parseToken(tokenStr)
	if err != nil {
		return "", err
	}
	return claims.Email, nil
}

func ValidateToken(tokenStr string) (*Claims, error) {
	claims, err := parseToken(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token has expired")
	}
	return claims, nil
}

func parseToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
