package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name               string             `bson:"name" json:"name"`
	LastName           string             `bson:"lastName" json:"lastName"`
	Username           string             `bson:"username" json:"username"`
	Password           string             `bson:"password" json:"password"`
	Email              string             `bson:"email" json:"email"`
	Role               string             `bson:"role" json:"role"`
	IsActive           bool               `bson:"isActive" json:"isActive"`
	VerificationCode   string             `bson:"verificationCode" json:"verificationCode"`
	VerificationExpiry time.Time          `bson:"verificationExpiry" json:"verificationExpiry"`
}
