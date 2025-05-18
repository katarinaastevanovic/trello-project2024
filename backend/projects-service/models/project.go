package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Project struct {
	ID              primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Name            string               `bson:"name" json:"name"`
	Description     string               `bson:"description" json:"description"`
	ExpectedEndDate time.Time            `json:"expectedEndDate" bson:"expected_end_date"`
	MinMembers      int                  `json:"minMembers" bson:"min_members"`
	MaxMembers      int                  `json:"maxMembers" bson:"max_members"`
	ManagerID       primitive.ObjectID   `json:"managerId" bson:"manager_id"`
	Members         []Member             `bson:"members" json:"members"`
	Tasks           []primitive.ObjectID `bson:"taskIDs" json:"taskIds"`
}
