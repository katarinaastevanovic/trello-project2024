package repositories

import (
	"log"
	"notifications-service/models"
	"os"
	"time"

	"github.com/gocql/gocql"
)

type NotificationRepo struct {
	session *gocql.Session
	logger  *log.Logger
}

// Konstruktor za povezivanje na Cassandra bazu
func NewNotificationRepo(logger *log.Logger) (*NotificationRepo, error) {
	db := os.Getenv("CASS_DB") // Preuzimanje konfiguracije iz okruženja
	if db == "" {
		db = "127.0.0.1" // Podrazumevana vrednost za lokalnu Cassandru
	}

	cluster := gocql.NewCluster(db)
	cluster.Keyspace = "system"
	session, err := cluster.CreateSession()
	if err != nil {
		logger.Println(err)
		return nil, err
	}

	// Kreiranje keyspace-a ako ne postoji
	err = session.Query(
		`CREATE KEYSPACE IF NOT EXISTS notifications 
         WITH replication = {
             'class': 'SimpleStrategy',
             'replication_factor': 1
         }`).Exec()
	if err != nil {
		logger.Println("Failed to create keyspace:", err)
		return nil, err
	}
	session.Close()

	// Povezivanje na keyspace notifications
	cluster.Keyspace = "notifications"
	cluster.Consistency = gocql.One
	session, err = cluster.CreateSession()
	if err != nil {
		logger.Println("Failed to connect to notifications keyspace:", err)
		return nil, err
	}

	logger.Println("Connected to Cassandra notifications keyspace.")
	return &NotificationRepo{
		session: session,
		logger:  logger,
	}, nil
}

// Funkcija za zatvaranje sesije
func (nr *NotificationRepo) CloseSession() {
	nr.session.Close()
	nr.logger.Println("Cassandra session closed.")
}

// Kreiranje tabele za notifikacije
func (nr *NotificationRepo) CreateTable() {
	err := nr.session.Query(
		`CREATE TABLE IF NOT EXISTS notifications (
			id UUID,
			username TEXT,
			user_id TEXT,
			message TEXT,
			created_at TIMESTAMP,
			is_read BOOLEAN,
			PRIMARY KEY ((username), created_at, id)
		) WITH CLUSTERING ORDER BY (created_at DESC, id ASC)`).Exec()
	if err != nil {
		nr.logger.Println("Failed to create notifications table:", err)
	} else {
		nr.logger.Println("Notifications table created successfully!")
	}
}

func (nr *NotificationRepo) CreateNotification(notification *models.Notification) error {
	if notification.ID == "" {
		notification.ID = gocql.TimeUUID().String()
	}

	err := nr.session.Query(
		`INSERT INTO notifications (id, username, user_id, message, created_at, is_read)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		notification.ID, notification.Username, notification.UserID, notification.Message, notification.CreatedAt, notification.IsRead,
	).Exec()
	if err != nil {
		nr.logger.Println("Greška prilikom kreiranja notifikacije:", err)
		return err
	}

	nr.logger.Println("Notifikacija uspešno kreirana!")
	return nil
}

func (nr *NotificationRepo) GetNotificationsByUsername(username string) ([]models.Notification, error) {
	query := `SELECT id, user_id, username, message, created_at, is_read 
			  FROM notifications WHERE username = ?`

	// Iteriraj kroz rezultate
	iter := nr.session.Query(query, username).Iter()
	var notifications []models.Notification
	var notification models.Notification

	for iter.Scan(&notification.ID, &notification.UserID, &notification.Username,
		&notification.Message, &notification.CreatedAt, &notification.IsRead) {
		notifications = append(notifications, notification)
	}

	if err := iter.Close(); err != nil {
		nr.logger.Println("Greška prilikom preuzimanja notifikacija po username-u:", err)
		return nil, err
	}

	return notifications, nil
}

func (nr *NotificationRepo) MarkNotificationAsRead(username, notificationID, createdAt string) error {
	// Parsiranje UUID-a za `id`
	uuid, err := gocql.ParseUUID(notificationID)
	if err != nil {
		nr.logger.Println("Invalid UUID format:", err)
		return err
	}

	// Parsiranje vremena za `created_at`
	parsedCreatedAt, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		nr.logger.Println("Invalid created_at format:", err)
		return err
	}

	// Ažuriranje u Cassandri
	query := `UPDATE notifications SET is_read = true WHERE username = ? AND id = ? AND created_at = ?`
	err = nr.session.Query(query, username, uuid, parsedCreatedAt).Exec()
	if err != nil {
		nr.logger.Println("Greška prilikom ažuriranja notifikacije:", err)
		return err
	}

	nr.logger.Println("Notifikacija uspešno označena kao pročitana!")
	return nil
}

func (nr *NotificationRepo) DeleteNotification(username, notificationID, createdAt string) error {
	// Provera ulaznih podataka
	nr.logger.Printf("Received for deletion: username=%s, id=%s, created_at=%s\n", username, notificationID, createdAt)

	// Konverzija UUID iz stringa
	uuid, err := gocql.ParseUUID(notificationID)
	if err != nil {
		nr.logger.Println("Invalid UUID format:", err)
		return err
	}
	nr.logger.Printf("Parsed UUID: %s\n", uuid)

	// Konverzija vremena
	parsedCreatedAt, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		nr.logger.Println("Invalid created_at format:", err)
		return err
	}
	nr.logger.Printf("Parsed CreatedAt: %s\n", parsedCreatedAt)

	// Izvršavanje upita
	query := `DELETE FROM notifications WHERE username = ? AND id = ? AND created_at = ?`
	err = nr.session.Query(query, username, uuid, parsedCreatedAt).Exec()
	if err != nil {
		nr.logger.Println("Greška prilikom brisanja notifikacije:", err)
		return err
	}

	nr.logger.Println("Notifikacija uspešno obrisana!")
	return nil
}
