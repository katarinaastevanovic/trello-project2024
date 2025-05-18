package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ProjectAnalytics struct {
	ProjectID           primitive.ObjectID                              `json:"projectId" bson:"projectId"`
	TotalTasks          int                                             `json:"totalTasks" bson:"totalTasks"`
	TasksByStatus       map[string]int                                  `json:"tasksByStatus" bson:"tasksByStatus"`
	TaskTimeInStatus    map[primitive.ObjectID]map[string]time.Duration `json:"taskTimeInStatus" bson:"taskTimeInStatus"`
	UserTaskAssignments map[primitive.ObjectID][]primitive.ObjectID     `json:"userTaskAssignments" bson:"userTaskAssignments"`
	IsCompletedOnTime   bool                                            `json:"isCompletedOnTime" bson:"isCompletedOnTime"`
}
