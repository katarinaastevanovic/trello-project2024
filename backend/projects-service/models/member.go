package models

import "go.mongodb.org/mongo-driver/bson/primitive"

type Member struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name     string             `bson:"name" json:"name"`
	LastName string             `bson:"lastName" json:"lastName"`
	Username string             `bson:"username" json:"username"`
	Role     string             `bson:"role" json:"role"`
}
