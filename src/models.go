package main

import "gorm.io/gorm"

// User - a simple user type
type User struct {
	gorm.Model
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty" binding:"required"`
	Password string `json:"password,omitempty" binding:"required"`
	Salt     string
}
