package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Task struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	ProjectID   string               `bson:"project_id" json:"project_id"`
	Title       string               `bson:"title" json:"title"`
	Description string               `bson:"description" json:"description"`
	Status      string               `bson:"status" json:"status"`
	Assignees   []primitive.ObjectID `bson:"assignees" json:"assignees"`
}
