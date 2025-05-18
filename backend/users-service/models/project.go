package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Project struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name            string             `bson:"name" json:"name"`
	Description     string             `bson:"description" json:"description"`
	ManagerID       primitive.ObjectID `bson:"manager_id" json:"managerId"`
	ExpectedEndDate time.Time          `bson:"expected_end_date" json:"expectedEndDate"`
	Tasks           []Task             `bson:"tasks" json:"tasks"`
	Members         []User             `bson:"members" json:"members"`
}
