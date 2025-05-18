package main

import (
	"context"

	"log"
	"net/http"
	"time"
	"trello-project/microservices/tasks-service/handlers"
	"trello-project/microservices/tasks-service/services"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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
	// Učitavanje .env fajla
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tasksClient, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://mongo-tasks:27017"))
	if err != nil {
		log.Fatal("Database connection for mongo-tasks failed:", err)
	}
	defer tasksClient.Disconnect(ctx)

	projectsClient, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://mongo-projects:27017"))
	if err != nil {
		log.Fatal("Database connection for mongo-projects failed:", err)
	}
	defer projectsClient.Disconnect(ctx)

	if err := tasksClient.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB connection error for mongo-tasks:", err)
	}
	if err := projectsClient.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB connection error for mongo-projects:", err)
	}

	// Kolekcije
	tasksCollection := tasksClient.Database("mongo-tasks").Collection("tasks")

	// Servis i handler
	taskService := services.NewTaskService(tasksCollection)
	taskHandler := handlers.NewTaskHandler(taskService)

	// Kreiranje mux routera
	r := mux.NewRouter()

	// Definisanje rute sa parametrima za zadatke i članove
	r.HandleFunc("/api/tasks/{taskID}/project/{projectID}/available-members", taskHandler.GetAvailableMembersForTask).Methods(http.MethodGet)
	r.HandleFunc("/api/tasks/{taskID}/add-members", taskHandler.AddMembersToTask).Methods(http.MethodPost)
	r.HandleFunc("/api/tasks/{taskID}/members", taskHandler.GetMembersForTaskHandler).Methods(http.MethodGet)
	r.HandleFunc("/api/tasks/{taskID}/members/{memberID}", taskHandler.RemoveMemberFromTaskHandler).Methods(http.MethodDelete)
	r.HandleFunc("/api/tasks/all", taskHandler.GetAllTasks).Methods("GET")                         // Prikaz svih zadataka
	r.HandleFunc("/api/tasks/create", taskHandler.CreateTask).Methods("POST")                      // Kreiranje novog zadatka
	r.HandleFunc("/api/tasks/project/{projectId}", taskHandler.GetTasksByProjectID).Methods("GET") // Zadatke po ID-u projekta
	r.HandleFunc("/api/tasks/status", taskHandler.ChangeTaskStatus).Methods("POST")
	r.HandleFunc("/api/tasks/project/{projectId}", taskHandler.DeleteTasksByProjectHandler).Methods(http.MethodDelete)

	// Svi ostali taskovi
	r.HandleFunc("/api/tasks", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			taskHandler.CreateTask(w, r)
		case http.MethodGet:
			taskHandler.GetAllTasks(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})
	// Pokretanje servera
	log.Println("Server running on http://localhost:8002")
	if err := http.ListenAndServe(":8002", enableCORS(r)); err != nil {
		log.Fatal(err)
	}

}
