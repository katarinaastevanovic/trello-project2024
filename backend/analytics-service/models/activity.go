package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type ActivityType string

const (
	ActivityAddMember         ActivityType = "AddMember"
	ActivityRemoveMember      ActivityType = "RemoveMember"
	ActivityCreateTask        ActivityType = "CreateTask"
	ActivityDeleteTask        ActivityType = "DeleteTask"
	ActivityChangeTaskStatus  ActivityType = "ChangeTaskStatus"
	ActivityAddDocumentToTask ActivityType = "AddDocumentToTask"
)

type ProjectActivity struct {
	ID           primitive.ObjectID  `json:"id" bson:"_id,omitempty"`
	ProjectID    primitive.ObjectID  `json:"projectId" bson:"projectId"`
	ActivityType ActivityType        `json:"activityType" bson:"activityType"`
	TaskID       *primitive.ObjectID `json:"taskId,omitempty" bson:"taskId,omitempty"`
	MemberID     *primitive.ObjectID `json:"memberId,omitempty" bson:"memberId,omitempty"`
	Timestamp    time.Time           `json:"timestamp" bson:"timestamp"`
	Details      string              `json:"details" bson:"details"`
}
