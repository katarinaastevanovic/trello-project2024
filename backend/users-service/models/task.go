package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Task struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	ProjectID   string               `bson:"project_id" json:"projectId"`
	Title       string               `bson:"title" json:"title"`
	Description string               `bson:"description" json:"description"`
	Status      string               `bson:"status" json:"status"` // "completed" ili "in_progress"
	Assignees   []primitive.ObjectID `bson:"assignees" json:"assignees"`
}
