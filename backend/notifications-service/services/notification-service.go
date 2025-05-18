package services

import (
	"fmt"
	"notifications-service/models"
	"notifications-service/repositories"
	"time"
)

type NotificationService struct {
	repo *repositories.NotificationRepo
}

// Konstruktor za NotificationService
func NewNotificationService(repo *repositories.NotificationRepo) *NotificationService {
	return &NotificationService{
		repo: repo,
	}
}

// Kreiranje nove notifikacije
func (ns *NotificationService) CreateNotification(userID, username, message string) error {
	if userID == "" || username == "" || message == "" {
		return fmt.Errorf("userID, username, and message are required")
	}
	notification := models.Notification{
		ID:        "", // ID će biti generisan u repozitorijumu
		UserID:    userID,
		Username:  username,
		Message:   message,
		CreatedAt: time.Now(),
		IsRead:    false,
	}
	return ns.repo.CreateNotification(&notification)
}

// Dohvatanje svih notifikacija za korisnika
func (ns *NotificationService) GetNotificationsByUsername(username string) ([]models.Notification, error) {
	return ns.repo.GetNotificationsByUsername(username)
}

// Ažuriranje notifikacije (označavanje kao pročitano)
func (ns *NotificationService) MarkNotificationAsRead(username, notificationID, createdAt string) error {
	if username == "" || notificationID == "" || createdAt == "" {
		return fmt.Errorf("username, notificationID, and createdAt are required")
	}

	return ns.repo.MarkNotificationAsRead(username, notificationID, createdAt)
}

// Brisanje notifikacije
func (ns *NotificationService) DeleteNotification(username, notificationID, createdAt string) error {
	return ns.repo.DeleteNotification(username, notificationID, createdAt)
}
