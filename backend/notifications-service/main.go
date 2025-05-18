package main

import (
	"log"
	"net/http"
	"notifications-service/handlers"
	"notifications-service/repositories"
	"notifications-service/services"
	"os"

	"github.com/gorilla/mux"
)

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://localhost:4200")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Role, Manager-ID")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
func main() {

	logger := log.New(os.Stdout, "notifications-service ", log.LstdFlags)

	// Inicijalizacija repozitorijuma
	repo, err := repositories.NewNotificationRepo(logger)
	if err != nil {
		logger.Fatalf("Failed to initialize repository: %v", err)
	}
	defer repo.CloseSession()

	// Kreiranje tabele ako ne postoji
	repo.CreateTable()

	// Inicijalizacija servisa
	service := services.NewNotificationService(repo)

	// Inicijalizacija handler-a
	handler := handlers.NewNotificationHandler(service)

	// Postavljanje ruter-a sa prefiksom /api/notifications
	router := mux.NewRouter()
	router.HandleFunc("/api/notifications/add", handler.CreateNotification).Methods("POST")
	router.HandleFunc("/api/notifications/{username}", handler.GetNotificationsByUsername).Methods("GET")
	router.HandleFunc("/api/notifications/read", handler.MarkNotificationAsRead).Methods("PUT")
	router.HandleFunc("/api/notifications/delete", handler.DeleteNotification).Methods("DELETE")
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Notifications service is running"))
	}).Methods("GET")

	corsRouter := enableCORS(router)

	// Pokretanje servera
	logger.Println("Server is running on port 8004")
	log.Fatal(http.ListenAndServe(":8004", corsRouter))
}
