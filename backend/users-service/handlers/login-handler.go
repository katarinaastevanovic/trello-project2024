package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"trello-project/microservices/users-service/models"
	"trello-project/microservices/users-service/services"
	"trello-project/microservices/users-service/utils"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	CaptchaToken string `json:"captchaToken"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type LoginHandler struct {
	UserService *services.UserService
	JWTService  *services.JWTService
}

type ForgotPasswordRequest struct {
	Username string `json:"username"`
}

func (h *LoginHandler) CheckUsername(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager", "member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	var user models.User
	err := h.UserService.UserCollection.FindOne(context.Background(), bson.M{"username": username}).Decode(&user)
	if err != nil {
		http.Error(w, "Username not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("true"))
}

func (h *LoginHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	err := h.UserService.SendPasswordResetLink(req.Username, req.Email)
	if err != nil {
		http.Error(w, "Failed to send reset link: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Password reset link sent successfully"))
}

func validateCredentials(username, password string) bool {
	if len(username) < 3 || len(username) > 20 {
		return false
	}
	if len(password) < 6 || len(password) > 20 {
		return false
	}
	return true
}

func (h *LoginHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validacija CAPTCHA tokena
	if req.CaptchaToken == "" {
		http.Error(w, "Missing CAPTCHA token", http.StatusBadRequest)
		return
	}

	isValid, err := utils.VerifyCaptcha(req.CaptchaToken)
	if err != nil || !isValid {
		http.Error(w, "Invalid CAPTCHA token", http.StatusForbidden)
		return
	}

	if !validateCredentials(req.Username, req.Password) {
		http.Error(w, "Invalid credentials format", http.StatusBadRequest)
		return
	}

	// Pozivamo funkciju LoginUser iz servisa koja vraća korisnika i token
	user, token, err := h.UserService.LoginUser(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	response := LoginResponse{
		Token:    token,
		Username: user.Username,
		Role:     user.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

//magic

type MagicLinkRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

func (h *LoginHandler) MagicLink(w http.ResponseWriter, r *http.Request) {
	// Dekodiraj telo zahteva u MagicLinkRequest strukturu
	var req MagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	log.Printf("Received magic link request: %+v", req)

	// Pronađi korisnika u bazi podataka
	var user models.User
	err := h.UserService.UserCollection.FindOne(context.Background(), bson.M{"username": req.Username}).Decode(&user)
	if err != nil {
		log.Printf("User not found for username: %s, error: %v", req.Username, err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	log.Printf("User found: %+v", user)

	if user.Email != req.Email {
		log.Printf("Email mismatch: expected %s, got %s", user.Email, req.Email)
		http.Error(w, "Email does not match", http.StatusBadRequest)
		return
	}

	// Generiši JWT token sa username i role
	token, err := h.JWTService.GenerateMagicLinkToken(req.Username, user.Role)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	log.Printf("Generated token: %s", token)

	// Kreiraj magic link koji se šalje korisniku
	magicLink := fmt.Sprintf("https://localhost:4200/magic-login?token=%s", token)
	log.Printf("Generated magic link: %s", magicLink)

	subject := "Your Magic Login Link"
	body := fmt.Sprintf("Click here to log in: %s", magicLink)
	if err := utils.SendEmail(req.Email, subject, body); err != nil {
		log.Printf("Failed to send email to %s: %v", req.Email, err)
		http.Error(w, "Failed to send email", http.StatusInternalServerError)
		return
	}
	log.Printf("Magic link successfully sent to: %s", req.Email)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Magic link sent successfully"))
	log.Println("Magic link request processed successfully")
}

// Funkcija za prijavu putem magic link-a
func (h *LoginHandler) MagicLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Token is missing", http.StatusBadRequest)
		return
	}

	claims, err := h.JWTService.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	//novi token za sesiju
	authToken, err := h.JWTService.GenerateAuthToken(claims.Username, claims.Role)
	if err != nil {
		http.Error(w, "Failed to generate auth token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"token":    authToken,
		"username": claims.Username,
		"role":     claims.Role,
	}

	fmt.Println("Backend response:", response)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Funkcija za verifikaciju magic linka i automatsku prijavu
func (h *LoginHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	claims, err := h.JWTService.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	//novi token za sesiju
	authToken, err := h.JWTService.GenerateAuthToken(claims.Username, claims.Role)
	if err != nil {
		http.Error(w, "Failed to generate auth token", http.StatusInternalServerError)
		return
	}

	response := map[string]string{
		"token":    authToken,
		"username": claims.Username,
		"role":     claims.Role,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *LoginHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}

	// Decode JSON zahteva
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Proveri validnost tokena
	claims, err := h.JWTService.ValidateToken(req.Token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Validacija nove lozinke
	if err := h.UserService.ValidatePassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hashuj novu lozinku
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Ažuriraj lozinku korisnika
	_, err = h.UserService.UserCollection.UpdateOne(
		context.Background(),
		bson.M{"username": claims.Username},
		bson.M{"$set": bson.M{"password": string(hashedPassword)}},
	)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// Vraćanje JSON odgovora
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Password reset successfully",
	})
}
