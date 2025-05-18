package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"trello-project/microservices/projects-service/handlers"
	"trello-project/microservices/projects-service/services"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func createProjectNameIndex(collection *mongo.Collection) error {
	indexModel := mongo.IndexModel{
		Keys:    bson.M{"name": 1},
		Options: options.Index().SetUnique(true),
	}
	_, err := collection.Indexes().CreateOne(context.TODO(), indexModel)
	if err != nil {
		return fmt.Errorf("failed to create unique index on project name: %v", err)
	}
	fmt.Println("Unique index on project name created successfully")
	return nil
}

func main() {
	// Učitavanje .env fajla
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	secretKey := os.Getenv("JWT_SECRET")
	if secretKey == "" {
		log.Fatal("JWT_SECRET is not set in the environment variables")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	projectsClient, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://mongo-projects:27017"))
	if err != nil {
		log.Fatal("Database connection for mongo-projects failed:", err)
	}
	defer projectsClient.Disconnect(context.TODO())

	tasksClient, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://mongo-tasks:27017"))
	if err != nil {
		log.Fatal("Database connection for mongo-tasks failed:", err)
	}
	defer tasksClient.Disconnect(context.TODO())

	usersClient, err := mongo.Connect(context.TODO(), options.Client().ApplyURI("mongodb://mongo-users:27017"))
	if err != nil {
		log.Fatal("Database connection for mongo-users failed:", err)
	}
	defer usersClient.Disconnect(context.TODO())

	if err := projectsClient.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB connection error for mongo-projects:", err)
	}
	if err := tasksClient.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB connection error for mongo-tasks:", err)
	}
	if err := usersClient.Ping(ctx, nil); err != nil {
		log.Fatal("MongoDB connection error for mongo-users:", err)
	}

	projectsDB := projectsClient.Database("mongo-projects")
	tasksDB := tasksClient.Database("mongo-tasks")
	usersDB := usersClient.Database("mongo-users")

	projectService := &services.ProjectService{
		ProjectsCollection: projectsDB.Collection("projects"),
		TasksCollection:    tasksDB.Collection("tasks"),
		UsersCollection:    usersDB.Collection("users"),
	}

	// Kreiranje jedinstvenog indeksa
	if err := createProjectNameIndex(projectsDB.Collection("projects")); err != nil {
		log.Fatal(err)
	}

	projectHandler := handlers.NewProjectHandler(projectService)

	r := mux.NewRouter()
	r.HandleFunc("/api/projects/{projectId}/members/all", projectHandler.GetProjectMembersHandler).Methods("GET")
	r.HandleFunc("/api/projects/remove/{projectId}/members/{memberId}/remove", projectHandler.RemoveMemberFromProjectHandler).Methods("DELETE")
	r.HandleFunc("/api/projects/remove-member/{projectId}/{memberId}", projectHandler.RemoveAnyMemberHandler).Methods("DELETE")
	r.HandleFunc("/api/projects/add", projectHandler.CreateProject).Methods("POST")
	r.HandleFunc("/api/projects/{id}/members", projectHandler.AddMemberToProjectHandler).Methods("POST")
	r.HandleFunc("/api/projects/users", projectHandler.GetAllUsersHandler).Methods("GET")
	r.HandleFunc("/api/projects/all", projectHandler.ListProjectsHandler).Methods("GET")
	r.HandleFunc("/api/projects/username/{username}", handlers.GetProjectsByUsername(projectService)).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/projects/{id}", projectHandler.GetProjectByIDHandler).Methods("GET")
	r.HandleFunc("/api/projects/{id}/tasks", projectHandler.DisplayTasksForProjectHandler).Methods("GET")
	r.HandleFunc("/api/projects/{projectId}", projectHandler.RemoveProjectHandler).Methods(http.MethodDelete)
	r.HandleFunc("/api/projects/members", projectHandler.GetAllMembersHandler)
	r.HandleFunc("/api/projects/{projectId}/add-task", projectHandler.AddTaskToProjectHandler).Methods("POST")
	r.HandleFunc("/api/projects/user-projects/{userID}", projectHandler.GetUserProjectsHandler).Methods("GET")

	corsRouter := enableCORS(r)

	fmt.Println("Projects service server running on http://localhost:8003")
	log.Fatal(http.ListenAndServe(":8003", corsRouter))
}

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
