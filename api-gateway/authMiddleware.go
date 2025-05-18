package main

import (
	"api-gateway/utils"
	"fmt"
	"net/http"
	"strings"
)

func authMiddleware(next http.Handler, allowedRoles []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		// Ekstrakcija tokena
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := utils.ValidateToken(tokenString) // Koristi funkciju za validaciju tokena
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Uzimanje uloge iz tokena
		userRole := claims.Role
		fmt.Println("User Role from Token:", userRole)

		if userRole == "" {
			http.Error(w, "Missing role in token", http.StatusUnauthorized)
			return
		}

		if !contains(allowedRoles, userRole) {
			http.Error(w, "Access forbidden", http.StatusForbidden)
			return
		}

		// Dodajemo ulogu u header pre nego što prosledimo dalje
		r.Header.Set("Role", userRole)
		fmt.Println("Role set in request header:", r.Header.Get("Role")) // Logovanje da proverimo da li je postavljena
		next.ServeHTTP(w, r)
	})
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
