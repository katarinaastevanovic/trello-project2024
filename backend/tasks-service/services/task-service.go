package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"time"
	"trello-project/microservices/tasks-service/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type TaskService struct {
	tasksCollection *mongo.Collection
}

func NewTaskService(tasksCollection *mongo.Collection) *TaskService {
	return &TaskService{
		tasksCollection: tasksCollection,
	}
}

func (s *TaskService) GetAvailableMembersForTask(r *http.Request, projectID, taskID string) ([]models.Member, error) {
	// Učitaj URL projects-service iz .env fajla
	projectsServiceURL := os.Getenv("PROJECTS_SERVICE_URL")
	if projectsServiceURL == "" {
		log.Println("PROJECTS_SERVICE_URL is not set in .env file")
		return nil, fmt.Errorf("projects-service URL is not configured")
	}

	// Napravi URL za HTTP GET zahtev ka projects-service
	url := fmt.Sprintf("%s/api/projects/%s/members/all", projectsServiceURL, projectID)
	log.Printf("Fetching project members from: %s", url)

	// Dohvati Authorization i Role iz dolaznog HTTP zahteva
	authToken := r.Header.Get("Authorization")
	userRole := r.Header.Get("Role")

	// Napravi HTTP zahtev sa zaglavljima
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Failed to create request to projects-service: %v", err)
		return nil, err
	}

	// Postavi potrebna zaglavlja
	req.Header.Set("Authorization", authToken)
	req.Header.Set("Role", userRole)

	// Pošalji zahtev
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch project members from projects-service: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Proveri statusni kod odgovora
	if resp.StatusCode != http.StatusOK {
		log.Printf("projects-service returned status: %d", resp.StatusCode)
		return nil, fmt.Errorf("failed to fetch project members, status: %d", resp.StatusCode)
	}

	// Dekodiraj JSON odgovor u listu članova
	var rawProjectMembers []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&rawProjectMembers); err != nil {
		log.Printf("Failed to decode response from projects-service: %v", err)
		return nil, err
	}

	// Konvertuj listu članova u models.Member sa ispravnim ID-jem
	var projectMembers []models.Member
	for _, rawMember := range rawProjectMembers {
		idStr, ok := rawMember["_id"].(string)
		if !ok {
			log.Printf("Warning: Member %+v has an invalid _id format", rawMember)
			continue
		}

		objectID, err := primitive.ObjectIDFromHex(idStr)
		if err != nil {
			log.Printf("Warning: Failed to convert member ID %s to ObjectID: %v", idStr, err)
			continue
		}

		member := models.Member{
			ID:       objectID,
			Name:     rawMember["name"].(string),
			LastName: rawMember["lastName"].(string),
			Username: rawMember["username"].(string),
			Role:     rawMember["role"].(string),
		}

		projectMembers = append(projectMembers, member)
	}

	// ✅ LOG: Članovi sa projekta pre bilo kakve obrade
	log.Printf("Project members fetched and converted for project %s: %+v", projectID, projectMembers)

	// Dohvati podatke o tasku
	taskObjectID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		log.Printf("Error converting taskID to ObjectID: %s, error: %v", taskID, err)
		return nil, fmt.Errorf("invalid task ID format")
	}

	var task models.Task
	err = s.tasksCollection.FindOne(context.Background(), bson.M{"_id": taskObjectID}).Decode(&task)
	if err != nil {
		log.Printf("Failed to fetch task members for taskID: %s, error: %v", taskID, err)
		return nil, fmt.Errorf("failed to fetch task members: %v", err)
	}

	// ✅ LOG: Članovi koji su već dodati na zadatak
	log.Printf("Task members fetched for task %s: %+v", taskID, task.Members)

	// Kreiraj mapu postojećih članova zadatka radi brže provere
	existingTaskMemberIDs := make(map[string]bool)
	for _, taskMember := range task.Members {
		existingTaskMemberIDs[taskMember.ID.Hex()] = true
	}

	// Dodaj u availableMembers samo one koji NISU u tasku
	availableMembers := []models.Member{}
	for _, member := range projectMembers {
		if _, exists := existingTaskMemberIDs[member.ID.Hex()]; !exists {
			log.Printf("Adding member %s to available list for task %s", member.Username, taskID)
			availableMembers = append(availableMembers, member)
		} else {
			log.Printf("Skipping member %s because they are already in task %s", member.Username, taskID)
		}
	}

	// ✅ LOG: Konačna lista dostupnih članova
	log.Printf("Final available members for task %s: %+v", taskID, availableMembers)

	return availableMembers, nil
}

// Dodaj članove zadatku
func (s *TaskService) AddMembersToTask(taskID string, membersToAdd []models.Member) error {
	// Konvertovanje taskID u ObjectID
	taskObjectID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return fmt.Errorf("invalid task ID format")
	}

	// Dohvati zadatak iz baze
	var task models.Task
	err = s.tasksCollection.FindOne(context.Background(), bson.M{"_id": taskObjectID}).Decode(&task)
	if err != nil {
		return fmt.Errorf("task not found: %v", err)
	}

	// Proveri i inicijalizuj polje `members` ako je `nil`
	if task.Members == nil {
		task.Members = []models.Member{}
		_, err := s.tasksCollection.UpdateOne(
			context.Background(),
			bson.M{"_id": taskObjectID},
			bson.M{"$set": bson.M{"members": task.Members}}, // Postavi `members` kao prazan niz
		)
		if err != nil {
			return fmt.Errorf("failed to initialize members field: %v", err)
		}
	}

	// Filtriraj nove članove koji nisu već dodeljeni
	newMembers := []models.Member{}
	for _, member := range membersToAdd {
		alreadyAssigned := false
		for _, assigned := range task.Members {
			if assigned.ID == member.ID {
				alreadyAssigned = true
				break
			}
		}
		if !alreadyAssigned {
			newMembers = append(newMembers, member)
		}
	}

	if len(newMembers) > 0 {
		// Ažuriraj zadatak sa novim članovima
		update := bson.M{"$addToSet": bson.M{"members": bson.M{"$each": newMembers}}}
		_, err = s.tasksCollection.UpdateOne(context.Background(), bson.M{"_id": taskObjectID}, update)
		if err != nil {
			return fmt.Errorf("failed to add members to task: %v", err)
		}

		// Slanje notifikacija za nove članove
		for _, member := range newMembers {
			message := fmt.Sprintf("You have been added to the task: %s!", task.Title)
			err = s.sendNotification(member, message)
			if err != nil {
				log.Printf("Failed to send notification to member %s: %v", member.Username, err)
				// Log greške, ali ne prekidaj proces
			}
		}
	}

	return nil
}
func (s *TaskService) sendNotification(member models.Member, message string) error {
	notification := map[string]string{
		"userId":   member.ID.Hex(),
		"username": member.Username,
		"message":  message, // Dinamična poruka
	}

	notificationData, err := json.Marshal(notification)
	if err != nil {
		fmt.Printf("Error marshaling notification data: %v\n", err)
		return nil
	}

	// Učitaj URL iz .env fajla
	notificationURL := os.Getenv("NOTIFICATIONS_SERVICE_URL")
	if notificationURL == "" {
		fmt.Println("Notification service URL is not set in .env")
		return fmt.Errorf("notification service URL is not configured")
	}

	req, err := http.NewRequest("POST", notificationURL, bytes.NewBuffer(notificationData))
	if err != nil {
		fmt.Printf("Error creating new request: %v\n", err)
		return nil
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Role", "manager")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending HTTP request: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Failed to create notification, status code: %d\n", resp.StatusCode)
		return nil
	}

	fmt.Printf("Notification successfully sent for member: %s\n", member.Username)
	return nil
}

// GetMembersForTask vraća listu članova koji su dodati na određeni task
func (s *TaskService) GetMembersForTask(taskID primitive.ObjectID) ([]models.Member, error) {
	var task models.Task

	// Dohvati zadatak iz baze koristeći ObjectID
	err := s.tasksCollection.FindOne(context.Background(), bson.M{"_id": taskID}).Decode(&task)
	if err != nil {
		log.Printf("Task not found: %v", err)
		return nil, fmt.Errorf("task not found")
	}

	// Vrati članove povezane sa zadatkom
	return task.Members, nil
}

func (s *TaskService) CreateTask(projectID string, title, description string, dependsOn *primitive.ObjectID, status models.TaskStatus) (*models.Task, error) {

	if dependsOn != nil {
		var dependentTask models.Task
		err := s.tasksCollection.FindOne(context.Background(), bson.M{"_id": *dependsOn}).Decode(&dependentTask)
		if err != nil {
			return nil, fmt.Errorf("dependent task not found")
		}
	}

	// Provera validnosti projectID
	_, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		return nil, fmt.Errorf("invalid project ID format: %v", err)
	}

	// Ako status nije prosleđen, postavljamo podrazumevanu vrednost
	if status == "" {
		status = models.StatusPending
	}

	// Sanitizacija inputa
	sanitizedTitle := html.EscapeString(title)
	sanitizedDescription := html.EscapeString(description)

	// Kreiranje objekta zadatka
	task := &models.Task{
		ID:          primitive.NewObjectID(),
		ProjectID:   projectID,
		Title:       sanitizedTitle,
		Description: sanitizedDescription,
		Status:      status,
		DependsOn:   dependsOn,
	}

	// Unos zadatka u tasks kolekciju
	result, err := s.tasksCollection.InsertOne(context.Background(), task)
	if err != nil {
		return nil, fmt.Errorf("failed to create task: %v", err)
	}

	// Ažuriramo ID zadatka na onaj koji je generisan prilikom unosa u bazu
	task.ID = result.InsertedID.(primitive.ObjectID)

	// 🔹 **Direktan HTTP zahtev ka `projects-service` za ažuriranje projekta**
	projectsServiceURL := os.Getenv("PROJECTS_SERVICE_URL")
	if projectsServiceURL == "" {
		log.Println("🚨 PROJECTS_SERVICE_URL is not set in .env file")
		return nil, fmt.Errorf("projects-service URL is not configured")
	}

	url := fmt.Sprintf("%s/api/projects/%s/add-task", projectsServiceURL, projectID)
	requestBody, err := json.Marshal(map[string]string{"taskID": task.ID.Hex()})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	log.Printf("🟢 Sending request to projects-service: %s", url)
	log.Printf("📨 Request body: %s", string(requestBody))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Postavljanje HTTP zaglavlja
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Role", "manager")

	// Slanje HTTP zahteva ka `projects-service`
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("🚨 Warning: Task was created, but failed to notify projects-service: %v", err)
		return task, nil // **Ne brišemo zadatak ako ovo ne uspe, samo logujemo grešku**
	}
	defer resp.Body.Close()

	// Provera statusa odgovora
	if resp.StatusCode != http.StatusOK {
		log.Printf("🚨 Warning: projects-service returned status %d when adding task %s to project %s", resp.StatusCode, task.ID.Hex(), projectID)
		return task, nil
	}

	log.Printf("✅ Successfully notified projects-service about new task %s for project %s", task.ID.Hex(), projectID)

	return task, nil
}

func (s *TaskService) GetAllTasks() ([]*models.Task, error) {
	var tasks []*models.Task
	cursor, err := s.tasksCollection.Find(context.Background(), bson.M{})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tasks: %v", err)
	}
	defer cursor.Close(context.Background())

	// Iteracija kroz sve zadatke
	for cursor.Next(context.Background()) {
		var task models.Task
		if err := cursor.Decode(&task); err != nil {
			return nil, fmt.Errorf("failed to decode task: %v", err)
		}
		tasks = append(tasks, &task)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %v", err)
	}

	return tasks, nil
}

func (s *TaskService) RemoveMemberFromTask(taskID string, memberID primitive.ObjectID) error {
	// Konvertovanje taskID u ObjectID
	taskObjectID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return fmt.Errorf("invalid task ID format")
	}

	// Dohvatanje zadatka iz baze
	var task models.Task
	err = s.tasksCollection.FindOne(context.Background(), bson.M{"_id": taskObjectID}).Decode(&task)
	if err != nil {
		return fmt.Errorf("task not found: %v", err)
	}

	// Provera da li je član deo zadatka
	memberFound := false
	var removedMember models.Member
	for i, member := range task.Members {
		if member.ID == memberID {
			removedMember = member
			task.Members = append(task.Members[:i], task.Members[i+1:]...)
			memberFound = true
			break
		}
	}

	if !memberFound {
		return fmt.Errorf("member not found in the task")
	}

	// Ažuriranje zadatka u bazi
	_, err = s.tasksCollection.UpdateOne(
		context.Background(),
		bson.M{"_id": taskObjectID},
		bson.M{"$set": bson.M{"members": task.Members}},
	)
	if err != nil {
		return fmt.Errorf("failed to update task: %v", err)
	}

	// Slanje notifikacije uklonjenom članu
	message := fmt.Sprintf("You have been removed from the task: %s", task.Title)
	err = s.sendNotification(removedMember, message)
	if err != nil {
		log.Printf("Failed to send notification to member %s: %v", removedMember.Username, err)
	}

	return nil
}

func (s *TaskService) GetTaskByID(taskID primitive.ObjectID) (*models.Task, error) {
	var task models.Task
	err := s.tasksCollection.FindOne(context.Background(), bson.M{"_id": taskID}).Decode(&task)
	if err != nil {
		return nil, err
	}
	return &task, nil
}

func (s *TaskService) GetTasksByProject(projectID string) ([]*models.Task, error) {
	var tasks []*models.Task

	filter := bson.M{"projectId": projectID}
	cursor, err := s.tasksCollection.Find(context.Background(), filter)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve tasks: %v", err)
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var task models.Task
		if err := cursor.Decode(&task); err != nil {
			return nil, fmt.Errorf("failed to decode task: %v", err)
		}
		tasks = append(tasks, &task)
	}

	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("cursor error: %v", err)
	}

	return tasks, nil
}

func (s *TaskService) ChangeTaskStatus(taskID primitive.ObjectID, status models.TaskStatus, username string) (*models.Task, error) {
	// Pronađi zadatak u bazi
	var task models.Task
	if err := s.tasksCollection.FindOne(context.Background(), bson.M{"_id": taskID}).Decode(&task); err != nil {
		return nil, fmt.Errorf("task not found: %v", err)
	}

	fmt.Printf("Task '%s' current status: %s\n", task.Title, task.Status)
	fmt.Printf("Attempting to change status to: %s\n", status)

	// Proveri da li je korisnik zadužen za zadatak
	var isAuthorized bool
	for _, member := range task.Members {
		if member.Username == username {
			isAuthorized = true
			break
		}
	}

	if !isAuthorized {
		return nil, fmt.Errorf("user '%s' is not authorized to change the status of this task because they are not assigned to it", username)
	}

	// Ako postoji zavisni zadatak, proveri njegov status
	if task.DependsOn != nil {
		var dependentTask models.Task
		if err := s.tasksCollection.FindOne(context.Background(), bson.M{"_id": task.DependsOn}).Decode(&dependentTask); err != nil {
			return nil, fmt.Errorf("dependent task not found: %v", err)
		}

		if dependentTask.Status != models.StatusInProgress && dependentTask.Status != models.StatusCompleted && status != models.StatusPending {
			return nil, fmt.Errorf("cannot change status because dependent task '%s' is not in progress or completed", dependentTask.Title)
		}
	}

	// Ažuriraj status trenutnog zadatka
	update := bson.M{"$set": bson.M{"status": status}}
	_, err := s.tasksCollection.UpdateOne(context.Background(), bson.M{"_id": taskID}, update)
	if err != nil {
		return nil, fmt.Errorf("failed to update task status: %v", err)
	}

	// Osveži podatke zadatka nakon promene statusa
	if err := s.tasksCollection.FindOne(context.Background(), bson.M{"_id": taskID}).Decode(&task); err != nil {
		return nil, fmt.Errorf("failed to retrieve updated task: %v", err)
	}

	fmt.Printf("Status of task '%s' successfully updated to: %s\n", task.Title, status)

	// Pošalji notifikacije svim članovima zadatka
	message := fmt.Sprintf("The status of the task '%s' has been changed to: %s", task.Title, status)
	for _, member := range task.Members {
		err := s.sendNotification(member, message)
		if err != nil {
			log.Printf("Failed to send notification to member %s: %v", member.Username, err)
		}
	}

	return &task, nil
}
func (s *TaskService) DeleteTasksByProject(projectID string) error {
	// Filter za pronalaženje zadataka sa projectId
	filter := bson.M{"projectId": projectID}

	// Brisanje svih zadataka vezanih za projekat
	result, err := s.tasksCollection.DeleteMany(context.Background(), filter)
	if err != nil {
		log.Printf("Failed to delete tasks for project ID %s: %v", projectID, err)
		return fmt.Errorf("failed to delete tasks: %v", err)
	}

	log.Printf("Successfully deleted %d tasks for project ID %s", result.DeletedCount, projectID)
	return nil
}
