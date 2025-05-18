package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type TaskDependencyRelation struct {
	FromTaskID primitive.ObjectID `json:"fromTaskId" bson:"fromTaskId"`
	ToTaskID   primitive.ObjectID `json:"toTaskId" bson:"toTaskId"`
}
