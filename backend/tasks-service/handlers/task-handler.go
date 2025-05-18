package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"trello-project/microservices/tasks-service/models"
	"trello-project/microservices/tasks-service/services"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TaskHandler struct {
	service *services.TaskService
}

func NewTaskHandler(service *services.TaskService) *TaskHandler {
	return &TaskHandler{service: service}
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

func (h *TaskHandler) CreateTask(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	var task models.Task
	if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Ako status nije naveden, postavi ga na "pending"
	if task.Status == "" {
		task.Status = models.StatusPending
	}

	// Sada prosleđujemo status prilikom kreiranja taska
	createdTask, err := h.service.CreateTask(task.ProjectID, task.Title, task.Description, task.DependsOn, task.Status)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdTask)
}

func (h *TaskHandler) GetAllTasks(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager", "member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	tasks, err := h.service.GetAllTasks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tasks)
}
func (h *TaskHandler) GetAvailableMembersForTask(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	taskID := vars["taskID"]
	projectID := vars["projectID"]

	log.Printf("Extracted taskID: %s, projectID: %s", taskID, projectID)

	// Ako nedostaju taskID ili projectID, vraćamo grešku
	if taskID == "" || projectID == "" {
		http.Error(w, "taskID or projectID is required", http.StatusBadRequest)
		return
	}

	// Pozivamo servis za dobijanje dostupnih članova - sada prosleđujemo i `r`
	members, err := h.service.GetAvailableMembersForTask(r, projectID, taskID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Vraćamo listu dostupnih članova
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(members)
}

func (h TaskHandler) GetTasksByProjectID(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager", "member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}

	// Loguj celu URL putanju
	log.Println("Requested URL:", r.URL.Path)

	// Ekstraktuj projectID
	projectID := strings.TrimPrefix(r.URL.Path, "/api/tasks/project/")
	log.Println("Extracted Project ID (before cleanup):", projectID)

	// Ukloni eventualne nepotrebne '/' karaktere
	projectID = strings.Trim(projectID, "/")
	log.Println("Extracted Project ID (after cleanup):", projectID)

	// Ako je projectID prazan, vrati grešku
	if projectID == "" {
		log.Println("Project ID is missing or empty!")
		http.Error(w, "Missing project ID", http.StatusBadRequest)
		return
	}

	// Pozovi servis i loguj rezultat
	log.Println("Fetching tasks for project ID:", projectID)
	tasks, err := h.service.GetTasksByProject(projectID)
	if err != nil {
		log.Println("Error fetching tasks for project ID:", projectID, "Error:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Loguj broj pronađenih zadataka
	log.Println("Number of tasks found:", len(tasks))

	// Vrati rezultate
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(tasks)
}

func (h *TaskHandler) AddMembersToTask(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	taskID := vars["taskID"]

	log.Printf("Task ID received: %s", taskID) // Dodaj log za Task ID

	var members []models.Member
	if err := json.NewDecoder(r.Body).Decode(&members); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	log.Printf("Members received: %+v", members) // Dodaj log za članove

	err := h.service.AddMembersToTask(taskID, members)
	if err != nil {
		log.Printf("Error adding members to task: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println("Members added successfully")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Members added successfully"}`))
}

// GetMembersForTaskHandler dohvaća članove dodeljene određenom tasku
func (h *TaskHandler) GetMembersForTaskHandler(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager", "member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	taskID := vars["taskID"]

	// Konverzija taskID u ObjectID
	taskObjectID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		log.Printf("Invalid task ID format: %v", err)
		http.Error(w, "Invalid task ID format", http.StatusBadRequest)
		return
	}

	// Pozovi servis za dobijanje članova zadatka
	members, err := h.service.GetMembersForTask(taskObjectID)
	if err != nil {
		log.Printf("Error fetching members for task: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Vrati članove kao odgovor
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(members)
}

// promena statusa
func (h TaskHandler) ChangeTaskStatus(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"member"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}

	var request struct {
		TaskID   string            `json:"taskId"`
		Status   models.TaskStatus `json:"status"`
		Username string            `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	taskObjectID, err := primitive.ObjectIDFromHex(request.TaskID)
	if err != nil {
		http.Error(w, "Invalid task ID format", http.StatusBadRequest)
		return
	}

	updatedTask, err := h.service.ChangeTaskStatus(taskObjectID, request.Status, request.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(updatedTask)
}

// RemoveMemberFromTaskHandler uklanja člana sa zadatka
func (h *TaskHandler) RemoveMemberFromTaskHandler(w http.ResponseWriter, r *http.Request) {
	if err := checkRole(r, []string{"manager"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}
	vars := mux.Vars(r)
	taskID := vars["taskID"]
	memberIDStr := vars["memberID"]

	// Konvertuj memberID u ObjectID
	memberID, err := primitive.ObjectIDFromHex(memberIDStr)
	if err != nil {
		http.Error(w, "Invalid member ID format", http.StatusBadRequest)
		return
	}

	// Pozivamo servis za uklanjanje člana
	err = h.service.RemoveMemberFromTask(taskID, memberID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Member %s removed successfully from task %s", memberIDStr, taskID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Member removed from task successfully and notification sent"}`))
}
func (h *TaskHandler) DeleteTasksByProjectHandler(w http.ResponseWriter, r *http.Request) {
	// Provera uloge korisnika
	if err := checkRole(r, []string{"manager"}); err != nil {
		http.Error(w, "Access forbidden: insufficient permissions", http.StatusForbidden)
		return
	}

	// Ekstrakcija projectId iz URL-a
	vars := mux.Vars(r)
	projectID := vars["projectId"]

	// Pozivanje servisa za brisanje zadataka
	err := h.service.DeleteTasksByProject(projectID)
	if err != nil {
		log.Printf("Failed to delete tasks for project ID %s: %v", projectID, err)
		http.Error(w, "Failed to delete tasks", http.StatusInternalServerError)
		return
	}

	// Uspešan odgovor
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Tasks deleted successfully"})
}
