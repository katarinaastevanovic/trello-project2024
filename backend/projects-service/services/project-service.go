package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"time"
	"trello-project/microservices/projects-service/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type ProjectService struct {
	ProjectsCollection *mongo.Collection
	TasksCollection    *mongo.Collection
	UsersCollection    *mongo.Collection
}

// NewProjectService initializes a new ProjectService with the necessary MongoDB collections.
func NewProjectService(projectsCollection, usersCollection, tasksCollection *mongo.Collection) *ProjectService {
	return &ProjectService{
		ProjectsCollection: projectsCollection,
		UsersCollection:    usersCollection,
		TasksCollection:    tasksCollection,
	}
}

// CreateProject creates a new project with the specified parameters.
func (s *ProjectService) CreateProject(name string, description string, expectedEndDate time.Time, minMembers, maxMembers int, managerID primitive.ObjectID) (*models.Project, error) {
	var existingProject models.Project
	err := s.ProjectsCollection.FindOne(context.Background(), bson.M{"name": name}).Decode(&existingProject)
	if err == nil {
		return nil, errors.New("project with the same name already exists")
	}

	if err != mongo.ErrNoDocuments {
		return nil, fmt.Errorf("database error: %v", err)
	}
	// Validate input parameters
	if minMembers < 1 || maxMembers < minMembers {
		return nil, fmt.Errorf("invalid member constraints: minMembers=%d, maxMembers=%d", minMembers, maxMembers)
	}
	if expectedEndDate.Before(time.Now()) {
		return nil, fmt.Errorf("expected end date must be in the future")
	}
	// Sanitizacija inputa
	sanitizedName := html.EscapeString(name)
	sanitizedDescription := html.EscapeString(description)

	// Create the project
	project := &models.Project{
		ID:              primitive.NewObjectID(),
		Name:            sanitizedName,
		Description:     sanitizedDescription,
		ExpectedEndDate: expectedEndDate,
		MinMembers:      minMembers,
		MaxMembers:      maxMembers,
		ManagerID:       managerID,
		Members:         []models.Member{},
		Tasks:           []primitive.ObjectID{},
	}

	// Insert the project into the collection
	result, err := s.ProjectsCollection.InsertOne(context.Background(), project)
	if err != nil {
		return nil, fmt.Errorf("failed to create project: %v", err)
	}

	// Set the project ID from the inserted result
	project.ID = result.InsertedID.(primitive.ObjectID)
	return project, nil
}

// AddMembersToProject adds multiple members to a project.
func (s *ProjectService) AddMembersToProject(projectID primitive.ObjectID, usernames []string) error {
	var project models.Project
	err := s.ProjectsCollection.FindOne(context.Background(), bson.M{"_id": projectID}).Decode(&project)
	if err != nil {
		log.Printf("Error finding project: %v\n", err)
		return fmt.Errorf("project not found: %v", err)
	}

	// Provera maksimalnog broja članova
	if len(project.Members)+len(usernames) > project.MaxMembers {
		log.Println("Maximum number of members reached for the project")
		return fmt.Errorf("maximum number of members reached for the project")
	}

	// Filtriranje članova koji su već na projektu
	existingMemberUsernames := make(map[string]bool)
	for _, member := range project.Members {
		existingMemberUsernames[member.Username] = true
	}

	var newUsernames []string
	for _, username := range usernames {
		if !existingMemberUsernames[username] {
			newUsernames = append(newUsernames, username)
		} else {
			log.Printf("Member %s is already in the project, skipping.\n", username)
		}
	}

	if len(newUsernames) == 0 {
		log.Println("No new members to add.")
		return fmt.Errorf("all provided members are already part of the project")
	}

	// Dohvatanje korisničkih podataka iz users-service pomoću username-a
	var members []models.Member
	usersServiceURL := os.Getenv("USERS_SERVICE_URL")
	for _, username := range newUsernames {
		fmt.Printf("Fetching user data from: %s/api/users/member/%s\n", usersServiceURL, username)
		resp, err := http.Get(fmt.Sprintf("%s/api/users/member/%s", usersServiceURL, username))
		if err != nil {
			log.Printf("Failed to fetch member %s: %v\n", username, err)
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Failed to fetch member %s, status code: %d\n", username, resp.StatusCode)
			return fmt.Errorf("failed to fetch member %s", username)
		}

		var user models.Member
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			log.Printf("Failed to decode member %s: %v\n", username, err)
			return err
		}

		members = append(members, user)
	}

	// Ažuriranje baze sa novim članovima
	filter := bson.M{"_id": projectID}
	update := bson.M{"$push": bson.M{"members": bson.M{"$each": members}}}
	_, err = s.ProjectsCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Printf("Error updating project members: %v\n", err)
		return err
	}

	log.Println("Members successfully added to the project.")
	return nil
}

func (s *ProjectService) sendNotification(member models.Member, message string) error {
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

// GetProjectMembers retrieves members of a specific project.
func (s *ProjectService) GetProjectMembers(ctx context.Context, projectID string) ([]bson.M, error) {
	projectObjectID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		fmt.Println("Invalid project ID format:", err)
		return nil, err
	}

	var project struct {
		Members []bson.M `bson:"members"`
	}

	err = s.ProjectsCollection.FindOne(ctx, bson.M{"_id": projectObjectID}).Decode(&project)
	if err != nil {
		fmt.Println("Error fetching project members from database:", err)
		return nil, err
	}

	return project.Members, nil
}

// GetAllUsers retrieves all users from the users collection.
func (s *ProjectService) GetAllUsers() ([]models.Member, error) {
	usersServiceURL := os.Getenv("USERS_SERVICE_URL")
	resp, err := http.Get(fmt.Sprintf("%s/api/users/members", usersServiceURL))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch users from users-service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("users-service returned status: %d", resp.StatusCode)
	}

	var users []models.Member
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("failed to decode response from users-service: %v", err)
	}

	return users, nil
}

// RemoveMemberFromProject removes a member from a project if they are not assigned to an in-progress task.
func (s *ProjectService) RemoveMemberFromProject(ctx context.Context, projectID, memberID string) error {
	projectObjectID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		return errors.New("invalid project ID format")
	}

	memberObjectID, err := primitive.ObjectIDFromHex(memberID)
	if err != nil {
		return errors.New("invalid member ID format")
	}

	// Proverite da li član ima aktivne zadatke
	taskFilter := bson.M{
		"projectId": projectObjectID.Hex(), // ID projekta
		"status":    "in progress",
		"assignees": memberObjectID, // ID člana
	}

	cursor, err := s.TasksCollection.Find(ctx, taskFilter)
	if err != nil {
		return errors.New("failed to check task assignments")
	}
	defer cursor.Close(ctx)

	// Proverite ima li aktivnih zadataka
	if cursor.TryNext(ctx) { // Ako postoje rezultati
		return errors.New("cannot remove member assigned to an in-progress task")
	}

	// Dohvati projekat za ime projekta
	var project models.Project
	err = s.ProjectsCollection.FindOne(ctx, bson.M{"_id": projectObjectID}).Decode(&project)
	if err != nil {
		return errors.New("project not found")
	}

	// Dohvati podatke o članu za notifikaciju
	var member models.Member
	err = s.UsersCollection.FindOne(ctx, bson.M{"_id": memberObjectID}).Decode(&member)
	if err != nil {
		return errors.New("member not found")
	}

	// Uklonite člana iz projekta
	projectFilter := bson.M{"_id": projectObjectID}
	update := bson.M{"$pull": bson.M{"members": bson.M{"_id": memberObjectID}}}

	result, err := s.ProjectsCollection.UpdateOne(ctx, projectFilter, update)
	if err != nil {
		return errors.New("failed to remove member from project")
	}

	if result.ModifiedCount == 0 {
		return errors.New("member not found in project or already removed")
	}

	// Slanje notifikacije nakon uspešnog uklanjanja
	message := fmt.Sprintf("You have been removed from the project: %s!", project.Name)
	err = s.sendNotification(member, message)
	if err != nil {
		log.Printf("Failed to send notification to member %s: %v\n", member.Username, err)
		// Log greške, ali ne prekidaj proces
	}

	return nil
}

// RemoveAnyMemberFromProject removes any member from a project.
func (s *ProjectService) RemoveAnyMemberFromProject(ctx context.Context, projectID, memberID string) error {
	projectObjectID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		return errors.New("invalid project ID format")
	}

	memberObjectID, err := primitive.ObjectIDFromHex(memberID)
	if err != nil {
		return errors.New("invalid member ID format")
	}

	// Uklonite člana iz projekta
	projectFilter := bson.M{"_id": projectObjectID}
	update := bson.M{"$pull": bson.M{"members": bson.M{"_id": memberObjectID}}}

	result, err := s.ProjectsCollection.UpdateOne(ctx, projectFilter, update)
	if err != nil {
		return errors.New("failed to remove member from project")
	}

	if result.ModifiedCount == 0 {
		return errors.New("member not found in project or already removed")
	}

	log.Printf("User %s removed from project %s", memberID, projectID)
	return nil
}

// GetAllProjects - preuzima sve projekte iz kolekcije
func (s *ProjectService) GetAllProjects() ([]models.Project, error) {
	var projects []models.Project
	cursor, err := s.ProjectsCollection.Find(context.Background(), bson.M{})
	if err != nil {
		return nil, fmt.Errorf("unsuccessful procurement of projects: %v", err)
	}
	defer cursor.Close(context.Background())

	if err = cursor.All(context.Background(), &projects); err != nil {
		return nil, fmt.Errorf("unsuccessful decoding of projects: %v", err)
	}

	return projects, nil
}

func (s *ProjectService) GetProjectByID(projectID string) (*models.Project, error) {
	objectId, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		fmt.Println("Invalid project ID format:", projectID)
		return nil, fmt.Errorf("invalid project ID format")
	}

	var project models.Project
	err = s.ProjectsCollection.FindOne(context.Background(), bson.M{"_id": objectId}).Decode(&project)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("error fetching project: %v", err)
	}
	return &project, nil
}

func (s *ProjectService) GetTasksForProject(projectID primitive.ObjectID, role string, authToken string) ([]*models.Task, error) {
	tasksServiceURL := os.Getenv("TASKS_SERVICE_URL")
	if tasksServiceURL == "" {
		return nil, fmt.Errorf("TASKS_SERVICE_URL not set")
	}

	url := fmt.Sprintf("%s/api/tasks/project/%s", tasksServiceURL, projectID.Hex())
	fmt.Printf("Fetching tasks from: %s\n", url)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Role", role)
	req.Header.Set("Authorization", authToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to fetch tasks for project %s: %v\n", projectID.Hex(), err)
		return nil, fmt.Errorf("failed to fetch tasks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to fetch tasks for project %s, status code: %d\n", projectID.Hex(), resp.StatusCode)
		return nil, fmt.Errorf("failed to fetch tasks, status code: %d", resp.StatusCode)
	}

	var tasks []*models.Task
	if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
		log.Printf("Failed to decode tasks response: %v\n", err)
		return nil, fmt.Errorf("failed to decode tasks: %v", err)
	}

	return tasks, nil
}

func (s *ProjectService) GetProjectsByUsername(username string) ([]models.Project, error) {
	var projects []models.Project
	filter := bson.M{"members.username": username}

	log.Printf("Executing MongoDB query with filter: %v", filter)

	cursor, err := s.ProjectsCollection.Find(context.Background(), filter)
	if err != nil {
		log.Printf("Error fetching projects from MongoDB: %v", err)
		return nil, fmt.Errorf("error fetching projects: %v", err)
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var project models.Project
		if err := cursor.Decode(&project); err != nil {
			log.Printf("Error decoding project document: %v", err)
			return nil, fmt.Errorf("error decoding project: %v", err)
		}
		projects = append(projects, project)
	}

	if err := cursor.Err(); err != nil {
		log.Printf("Cursor error: %v", err)
		return nil, fmt.Errorf("cursor error: %v", err)
	}

	log.Printf("Found %d projects for username %s", len(projects), username)
	return projects, nil
}

func (s *ProjectService) DeleteProjectAndTasks(ctx context.Context, projectID string, r *http.Request) error {
	// Konverzija projectID u ObjectID
	projectObjectID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		log.Printf("Invalid project ID format: %v", projectID)
		return fmt.Errorf("invalid project ID format")
	}

	// Provera postojanja projekta
	filter := bson.M{"_id": projectObjectID}
	var project bson.M
	err = s.ProjectsCollection.FindOne(ctx, filter).Decode(&project)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			log.Printf("Project not found: %v", projectID)
			return fmt.Errorf("project not found")
		}
		log.Printf("Failed to fetch project: %v", err)
		return fmt.Errorf("failed to fetch project: %v", err)
	}

	// Priprema zahteva za tasks-service
	taskServiceURL := "http://tasks-service:8002"
	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/tasks/project/%s", taskServiceURL, projectID), nil)
	if err != nil {
		log.Printf("Failed to create request to tasks-service: %v", err)
		return fmt.Errorf("failed to create request to task service: %v", err)
	}

	// Prosleđivanje zaglavlja
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("Role", r.Header.Get("Role"))

	// Slanje zahteva ka tasks-service
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send request to tasks-service: %v", err)
		return fmt.Errorf("failed to send request to task service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Tasks-service returned non-OK status: %v", resp.Status)
		return fmt.Errorf("task service returned an error: %v", resp.Status)
	}

	// Brisanje projekta iz baze
	_, err = s.ProjectsCollection.DeleteOne(ctx, filter)
	if err != nil {
		log.Printf("Failed to delete project: %v", err)
		return fmt.Errorf("failed to delete project: %v", err)
	}

	log.Printf("Successfully deleted project and related tasks for ID: %s", projectID)
	return nil
}

func (s *ProjectService) GetAllMembers() ([]models.Member, error) {
	// Učitaj URL `users-service` iz .env fajla
	usersServiceURL := os.Getenv("USERS_SERVICE_URL")
	if usersServiceURL == "" {
		log.Println("USERS_SERVICE_URL is not set in .env file")
		return nil, fmt.Errorf("users-service URL is not configured")
	}

	// Napravi HTTP GET zahtev
	resp, err := http.Get(usersServiceURL + "/api/users/members")
	if err != nil {
		log.Printf("Failed to fetch members from users-service: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("users-service returned non-200 status: %d", resp.StatusCode)
		return nil, fmt.Errorf("failed to get members, status: %d", resp.StatusCode)
	}

	// Dekodiraj odgovor
	var members []models.Member
	if err := json.NewDecoder(resp.Body).Decode(&members); err != nil {
		log.Printf("Failed to decode members response: %v", err)
		return nil, err
	}

	return members, nil
}

func (s *ProjectService) AddTaskToProject(projectID string, taskID string) error {
	projectObjectID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		return fmt.Errorf("invalid project ID format: %v", err)
	}

	taskObjectID, err := primitive.ObjectIDFromHex(taskID)
	if err != nil {
		return fmt.Errorf("invalid task ID format: %v", err)
	}

	log.Printf("🟢 Received request to add task %s to project %s", taskID, projectID)

	// Ažuriranje projekta dodavanjem ID-ja zadatka
	filter := bson.M{"_id": projectObjectID}
	update := bson.M{"$push": bson.M{"taskIDs": taskObjectID}}

	log.Printf("🔄 MongoDB filter: %+v", filter)
	log.Printf("🔄 MongoDB update: %+v", update)

	result, err := s.ProjectsCollection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		log.Printf("🚨 Failed to update project with task ID: %v", err)
		return fmt.Errorf("failed to update project with task ID: %v", err)
	}

	if result.ModifiedCount == 0 {
		log.Printf("⚠️ No project was updated. Possible that project ID %s does not exist.", projectID)
		return fmt.Errorf("no project found with ID %s", projectID)
	}

	log.Printf("✅ Task %s successfully added to project %s", taskID, projectID)
	return nil
}

func (s *ProjectService) RemoveUserFromProjects(userID string, role string) error {
	// Ako je korisnik menadžer, proveravamo da li ima projekte sa nedovršenim zadacima
	if role == "manager" {
		projectFilter := bson.M{"manager_id": userID}
		cursor, err := s.ProjectsCollection.Find(context.Background(), projectFilter)
		if err != nil {
			log.Printf("Error fetching projects for manager %s: %v\n", userID, err)
			return fmt.Errorf("failed to fetch projects")
		}
		defer cursor.Close(context.Background())

		// Proveravamo da li su zadaci u projektima završeni
		for cursor.Next(context.Background()) {
			var project models.Project
			if err := cursor.Decode(&project); err != nil {
				log.Printf("Error decoding project: %v\n", err)
				continue
			}

			taskFilter := bson.M{"projectId": project.ID.Hex(), "status": bson.M{"$ne": "Completed"}}
			count, err := s.TasksCollection.CountDocuments(context.Background(), taskFilter)
			if err != nil {
				log.Printf("Error checking unfinished tasks for project %s: %v\n", project.ID.Hex(), err)
				continue
			}

			if count > 0 {
				log.Printf("Cannot remove manager %s: unfinished tasks in project %s\n", userID, project.ID.Hex())
				return fmt.Errorf("manager cannot be removed from project %s due to unfinished tasks", project.ID.Hex())
			}
		}

		// Ako menadžer može biti uklonjen, brišemo ga iz projekata
		update := bson.M{"$unset": bson.M{"manager_id": ""}}
		_, err = s.ProjectsCollection.UpdateMany(context.Background(), projectFilter, update)
		if err != nil {
			log.Printf("Failed to remove manager %s from projects: %v\n", userID, err)
			return fmt.Errorf("failed to update projects")
		}
	}

	// Ako je korisnik član, brišemo ga iz members liste u projektima
	if role == "member" {
		filter := bson.M{"members._id": userID}
		update := bson.M{"$pull": bson.M{"members": bson.M{"_id": userID}}}
		_, err := s.ProjectsCollection.UpdateMany(context.Background(), filter, update)
		if err != nil {
			log.Printf("Failed to remove user %s from projects: %v\n", userID, err)
			return fmt.Errorf("failed to update projects")
		}
	}

	log.Printf("User %s successfully removed from all projects", userID)
	return nil
}

func (s *ProjectService) GetUserProjects(username string) ([]map[string]interface{}, error) {
	var response []map[string]interface{}

	filter := bson.M{"members.username": username}

	log.Printf("Executing MongoDB query with filter: %v", filter)

	cursor, err := s.ProjectsCollection.Find(context.Background(), filter)
	if err != nil {
		log.Printf("Error fetching projects from MongoDB: %v", err)
		return nil, fmt.Errorf("error fetching projects: %v", err)
	}
	defer cursor.Close(context.Background())

	for cursor.Next(context.Background()) {
		var project models.Project
		if err := cursor.Decode(&project); err != nil {
			log.Printf("Error decoding project document: %v", err)
			continue
		}

		// Konverzija ObjectID u string
		projectData := map[string]interface{}{
			"id":          project.ID.Hex(), // Rešava problem dekodiranja
			"name":        project.Name,
			"description": project.Description,
		}

		response = append(response, projectData)
	}

	if err := cursor.Err(); err != nil {
		log.Printf("Cursor error: %v", err)
		return nil, fmt.Errorf("cursor error: %v", err)
	}

	log.Printf("Found %d projects for user %s", len(response), username)
	return response, nil
}
