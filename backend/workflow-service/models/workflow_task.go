package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type WorkflowTask struct {
	TaskID      primitive.ObjectID `json:"taskId" bson:"taskId"`
	Title       string             `json:"title" bson:"title"`
	Description string             `json:"description" bson:"description"`
	IsBlocked   bool               `json:"isBlocked" bson:"isBlocked"`
}
