package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Workflow struct {
	ID           primitive.ObjectID       `json:"id" bson:"_id,omitempty"`
	ProjectID    primitive.ObjectID       `json:"projectId" bson:"projectId"`
	Tasks        []WorkflowTask           `json:"tasks" bson:"tasks"`
	Dependencies []TaskDependencyRelation `json:"dependencies" bson:"dependencies"`
}
