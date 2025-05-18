package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"trello-project/microservices/users-service/models"
	"trello-project/microservices/users-service/services"
	"trello-project/microservices/users-service/utils"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
)

type UserHandler struct {
	UserService *services.UserService
	JWTService  *services.JWTService
	BlackList   map[string]bool
}

func checkRole(r *http.Request, allowedRoles []string) error {
	userRole := r.Header.Get("Role")
	fmt.Println("User Role in Request Header:", userRole)

	if userRole == "" {
		return fmt.Errorf("role is missing in request header")
	}

	// Provera da li je uloga dozvoljena
	for _, role := range allowedRoles {
		if role == userRole {
			return nil
		}
	}
	return fmt.Errorf("access forbidden: user does not have the required role")
}

func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		User         models.User `json:"user"`
		CaptchaToken string      `json:"captchaToken"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	captchaToken := requestData.CaptchaToken
	if captchaToken == "" {
		http.Error(w, "Missing CAPTCHA token", http.StatusBadRequest)
		return
	}

	// Validacija CAPTCHA tokena
	isValid, err := utils.VerifyCaptcha(captchaToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("CAPTCHA validation failed: %v", err), http.StatusInternalServerError)
		return
	}
	if !isValid {
		http.Error(w, "CAPTCHA verification failed", http.StatusForbidden)
		return
	}

	user := requestData.User

	if err := h.UserService.ValidatePassword(user.Password); err != nil {
		log.Println("Password validation failed:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Password is too common. Please choose a stronger one.",
		})

		return
	}

	// Proveri da li korisničko ime već postoji
	var existingUser models.User
	err = h.UserService.UserCollection.FindOne(context.Background(), bson.M{"username": user.Username}).Decode(&existingUser)
	if err == nil {
		// Ako korisnik sa datim korisničkim imenom postoji, vraćamo grešku
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Nastavi sa registracijom korisnika
	err = h.UserService.RegisterUser(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Registration successful. Check your email for confirmation link."})
}

// ConfirmEmail kreira korisnika u bazi i redirektuje na login stranicu
func (h *UserHandler) ConfirmEmail(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Token string `json:"token"`
	}

	log.Println("Primljen zahtev za potvrdu emaila")

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		log.Println("Greška pri dekodiranju JSON-a:", err)
		return
	}

	// Verifikacija tokena
	email, err := h.UserService.JWTService.VerifyEmailVerificationToken(requestData.Token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		log.Println("Nevažeći ili istekao token za email:", email, "greška:", err)
		return
	}
	log.Println("Token verifikovan za email:", email)

	// Proveri da li postoji keširan token
	tokenData, ok := h.UserService.TokenCache[email]
	if !ok {
		http.Error(w, "Token expired or not found", http.StatusUnauthorized)
		log.Println("Token nije pronađen u kešu za:", email)
		return
	}

	// Parsiranje podataka iz keša
	dataParts := strings.Split(tokenData, "|")
	if len(dataParts) < 6 {
		http.Error(w, "Invalid token data", http.StatusBadRequest)
		log.Println("Nevažeći podaci u tokenu za:", email)
		return
	}
	name := dataParts[1]
	lastName := dataParts[2]
	username := dataParts[3]
	password := dataParts[4]
	role := dataParts[5]

	// Kreiraj korisnika sa dobijenim podacima i postavi IsActive na true
	user := models.User{
		Email:    email,
		Name:     name,
		LastName: lastName,
		Username: username,
		Password: password,
		Role:     role,
		IsActive: true,
	}

	// Čuvanje korisnika u bazi
	err = h.UserService.CreateUser(user)
	if err != nil {
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		log.Println("Greška pri čuvanju korisnika u bazi:", err)
		return
	}
	log.Println("Korisnik uspešno sačuvan:", user.Email)

	// Brisanje tokena iz keša nakon uspešne verifikacije
	delete(h.UserService.TokenCache, email)

	// Redirektovanje korisnika na login stranicu
	w.Header().Set("Location", "https://localhost:4200/login")
	w.WriteHeader(http.StatusFound)
}

func (h *UserHandler) VerifyCode(w http.ResponseWriter, r *http.Request) {
	var requestData struct {
		Username string `json:"username"`
		Code     string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		log.Println("Greška pri dekodiranju zahteva:", err)
		return
	}

	log.Println("Primljen zahtev za verifikaciju korisnika:", requestData.Username, "sa kodom:", requestData.Code)

	// Provera da li postoji korisnik sa datim username-om
	var user models.User
	err := h.UserService.UserCollection.FindOne(context.Background(), bson.M{"username": requestData.Username}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		log.Println("Korisnik nije pronađen sa username-om:", requestData.Username)
		return
	}

	log.Println("Pronađen korisnik:", user)

	// Provera da li se kod poklapa i da li je istekao
	if user.VerificationCode != requestData.Code || time.Now().After(user.VerificationExpiry) {
		log.Println("Nevažeći verifikacioni kod:", user.VerificationCode, "primljeni kod:", requestData.Code)
		// Brišemo korisnika jer kod nije validan ili je istekao
		_, delErr := h.UserService.UserCollection.DeleteOne(context.Background(), bson.M{"username": requestData.Username})
		if delErr != nil {
			log.Println("Greška prilikom brisanja korisnika:", delErr)
		}
		http.Error(w, "Invalid or expired code", http.StatusUnauthorized)
		return
	}

	// Postavljanje `IsActive` na `true` i brisanje verifikacionih podataka
	user.IsActive = true
	user.VerificationCode = ""
	user.VerificationExpiry = time.Time{} // Reset vremena isteka

	_, err = h.UserService.UserCollection.UpdateOne(context.Background(), bson.M{"username": requestData.Username}, bson.M{"$set": bson.M{
		"isActive":           true,
		"verificationCode":   "",
		"verificationExpiry": time.Time{},
	}})
	if err != nil {
		http.Error(w, "Failed to activate user", http.StatusInternalServerError)
		log.Println("Greška prilikom ažuriranja korisnika u bazi:", err)
		return
	}

	log.Println("Korisnik uspešno aktiviran:", user.Username)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("User verified and saved successfully."))
}

func (h *UserHandler) DeleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("🔹 [DEBUG] Full request URL:", r.URL.Path)

	vars := mux.Vars(r)
	fmt.Println("🔹 [DEBUG] Extracted Vars:", vars)

	username, exists := vars["username"]
	if !exists || username == "" {
		fmt.Println("❌ [ERROR] Username is missing in URL!")
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}

	fmt.Println("✅ [DEBUG] Extracted username:", username)

	// 🟢 Ekstrahujemo JWT token iz zaglavlja
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		fmt.Println("❌ [ERROR] Authorization token is missing!")
		http.Error(w, "Authorization token is required", http.StatusUnauthorized)
		return
	}

	// 🟢 Parsiramo JWT token i vadimo rolu korisnika
	role, err := h.JWTService.ExtractRoleFromToken(strings.TrimPrefix(tokenString, "Bearer "))
	if err != nil {
		fmt.Println("❌ [ERROR] Failed to extract role from token:", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// 🟢 Prikaz korisničke role
	fmt.Println("✅ [DEBUG] User Role from Token:", role)

	// Proveravamo da li korisnik ima pravo da briše nalog
	if role != "manager" && role != "member" {
		fmt.Println("❌ [ERROR] Access forbidden: insufficient permissions for role:", role)
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}

	// 🔹 Brišemo nalog
	err = h.UserService.DeleteAccount(username, r)
	if err != nil {
		if strings.Contains(err.Error(), "unfinished tasks") {
			http.Error(w, err.Error(), http.StatusConflict) // HTTP 409: Conflict
		} else {
			http.Error(w, "Failed to delete account: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// ✅ Uspešno brisanje
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Account deleted successfully"})
}

func (h *UserHandler) GetUserForCurrentSession(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager", "member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	if len(tokenString) > 7 && strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = tokenString[7:]
	}

	claims, err := h.JWTService.ValidateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var user models.User
	err = h.UserService.UserCollection.FindOne(context.Background(), bson.M{"username": claims.Username}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	user.Password = ""
	user.VerificationCode = ""

	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		http.Error(w, "Failed to encode user data", http.StatusInternalServerError)
		return
	}
}

// ChangePassword menja lozinku korisniku
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager", "member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	var requestData struct {
		OldPassword     string `json:"oldPassword"`
		NewPassword     string `json:"newPassword"`
		ConfirmPassword string `json:"confirmPassword"`
	}

	// Parsiranje podataka iz zahteva
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	// Dohvati token iz Authorization header-a
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
		return
	}

	// Ako token počinje sa "Bearer ", ukloni ga
	if len(tokenString) > 7 && strings.HasPrefix(tokenString, "Bearer ") {
		tokenString = tokenString[7:]
	}

	// Validiraj token
	claims, err := h.JWTService.ValidateToken(tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Provera whitelist i blacklist pravila za novu lozinku
	if err := h.UserService.ValidatePassword(requestData.NewPassword); err != nil {
		log.Println("Password validation failed:", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Password is too common. Please choose a stronger one.",
		})

		return
	}

	// Pozovi servisnu metodu za promenu lozinke
	err = h.UserService.ChangePassword(claims.Username, requestData.OldPassword, requestData.NewPassword, requestData.ConfirmPassword)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Ako je uspešno, pošaljemo JSON odgovor
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := map[string]string{"message": "Password updated successfully"}
	json.NewEncoder(w).Encode(response)

}

// func (h *UserHandler) GetAllMembers(w http.ResponseWriter, r *http.Request) {
// 	// Pravljenje filtera koji selektuje samo korisnike čiji je role = "member"
// 	filter := bson.M{"role": "member"}

// 	// Izvršavanje upita na bazi
// 	cursor, err := h.UserService.UserCollection.Find(context.Background(), filter)
// 	if err != nil {
// 		http.Error(w, "Failed to fetch members", http.StatusInternalServerError)
// 		return
// 	}
// 	defer cursor.Close(context.Background())

// 	// Parsiranje rezultata
// 	var members []models.User
// 	if err := cursor.All(context.Background(), &members); err != nil {
// 		http.Error(w, "Failed to parse members", http.StatusInternalServerError)
// 		return
// 	}

// 	// Uklanjanje lozinki iz odgovora
// 	for i := range members {
// 		members[i].Password = ""
// 	}

// 	// Slanje JSON odgovora
// 	w.Header().Set("Content-Type", "application/json")
// 	w.WriteHeader(http.StatusOK)
// 	json.NewEncoder(w).Encode(members)
// }

func (h *UserHandler) GetMemberByUsernameHandler(w http.ResponseWriter, r *http.Request) {
	// Loguj celu putanju za debug
	path := r.URL.Path
	fmt.Printf("Full URL Path: %s\n", path)

	// Parsiraj username iz putanje
	parts := strings.Split(path, "/")
	if len(parts) < 5 { // Očekujemo da je username na kraju URL-a
		http.Error(w, "Invalid URL format", http.StatusBadRequest)
		return
	}

	username := parts[len(parts)-1]
	fmt.Printf("Extracted username manually: %s\n", username)

	// Ako je username prazan
	if username == "" {
		http.Error(w, "Username parameter is missing", http.StatusBadRequest)
		return
	}

	// Dohvatanje člana iz baze pomoću username-a
	var member models.User
	err := h.UserService.UserCollection.FindOne(r.Context(), bson.M{"username": username}).Decode(&member)
	if err != nil {
		fmt.Printf("User not found in database: %s, error: %v\n", username, err)
		http.Error(w, "Member not found", http.StatusNotFound)
		return
	}

	fmt.Printf("User found: %+v\n", member)

	// Kreiranje odgovora
	response := struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		LastName string `json:"lastName"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		IsActive bool   `json:"isActive"`
	}{
		ID:       member.ID.Hex(),
		Name:     member.Name,
		LastName: member.LastName,
		Username: member.Username,
		Email:    member.Email,
		Role:     member.Role,
		IsActive: member.IsActive,
	}

	// Slanje JSON odgovora
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *UserHandler) GetMembersByProjectIDHandler(w http.ResponseWriter, r *http.Request) {
	// Preuzmite projectId iz parametara URL-a
	vars := mux.Vars(r)
	projectID := vars["projectId"]

	// Kreirajte URL za poziv projects servisa
	projectsServiceURL := os.Getenv("PROJECTS_SERVICE_URL")
	url := fmt.Sprintf("%s/api/projects/%s/members/all", projectsServiceURL, projectID)

	// Pošaljite GET zahtev ka projects servisu
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, "Failed to communicate with projects service", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Projects service returned status %d", resp.StatusCode), http.StatusInternalServerError)
		return
	}

	// Pročitajte i prosledite odgovor klijentu
	var members []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		http.Error(w, "Failed to decode response from projects service", http.StatusInternalServerError)
		return
	}

	// Vratite podatke o članovima
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(members)
}

// vraca sve korisnike koji imaju role member
func (h *UserHandler) GetAllMembers(w http.ResponseWriter, r *http.Request) {
	// Pozovi servis da dobavi članove (users sa role = "member")
	members, err := h.UserService.GetAllMembers()
	if err != nil {
		http.Error(w, "Failed to fetch members", http.StatusInternalServerError)
		return
	}

	// Slanje JSON odgovora
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(members)
}
