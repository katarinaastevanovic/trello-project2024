package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"notifications-service/services"
)

type NotificationHandler struct {
	service *services.NotificationService
}

// Konstruktor za NotificationHandler
func NewNotificationHandler(service *services.NotificationService) *NotificationHandler {
	return &NotificationHandler{
		service: service,
	}
}
func checkRole(r *http.Request, allowedRoles []string) error {
	userRole := r.Header.Get("Role")
	if userRole == "" {
		return fmt.Errorf("role is missing in request header")
	}

	// Proveri da li je uloga dozvoljena
	for _, role := range allowedRoles {
		if role == userRole {
			return nil
		}
	}
	return fmt.Errorf("access forbidden: user does not have the required role")
}

// HTTP handler za kreiranje notifikacije
func (nh *NotificationHandler) CreateNotification(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	var req struct {
		UserID   string `json:"userId"`
		Username string `json:"username"`
		Message  string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.Username == "" || req.Message == "" {
		http.Error(w, "All fields (userId, username, message) are required", http.StatusBadRequest)
		return
	}

	if err := nh.service.CreateNotification(req.UserID, req.Username, req.Message); err != nil {
		http.Error(w, "Failed to create notification", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// HTTP handler za dobijanje notifikacija korisnika
func (nh *NotificationHandler) GetNotificationsByUsername(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "Missing username parameter", http.StatusBadRequest)
		return
	}

	notifications, err := nh.service.GetNotificationsByUsername(username)
	if err != nil {
		http.Error(w, "Failed to fetch notifications", http.StatusInternalServerError)
		return
	}
	if len(notifications) == 0 {
		http.Error(w, "No notifications found for the given username", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notifications)
}

// HTTP handler za označavanje notifikacije kao pročitane
func (nh *NotificationHandler) MarkNotificationAsRead(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NotificationID string `json:"notificationId"`
		Username       string `json:"username"`
		CreatedAt      string `json:"createdAt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.NotificationID == "" || req.Username == "" || req.CreatedAt == "" {
		http.Error(w, "Notification ID, Username, and CreatedAt are required", http.StatusBadRequest)
		return
	}

	if err := nh.service.MarkNotificationAsRead(req.Username, req.NotificationID, req.CreatedAt); err != nil {
		http.Error(w, "Failed to mark notification as read", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// HTTP handler za brisanje notifikacije
func (nh *NotificationHandler) DeleteNotification(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	var req struct {
		NotificationID string `json:"notificationId"`
		Username       string `json:"username"`
		CreatedAt      string `json:"createdAt"`
	}

	// Dekodiraj JSON payload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validacija
	if req.NotificationID == "" || req.Username == "" || req.CreatedAt == "" {
		http.Error(w, "Notification ID, Username, and CreatedAt are required", http.StatusBadRequest)
		return
	}

	// Poziv servisa
	if err := nh.service.DeleteNotification(req.Username, req.NotificationID, req.CreatedAt); err != nil {
		http.Error(w, "Failed to delete notification", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
