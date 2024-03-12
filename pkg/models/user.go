package models

import (
	"errors"
	"to-do-list/pkg/config"

	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	gorm.Model
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Tasks     []Task // Relationship: one-to-many with Task
}

var db *gorm.DB

// Initialize the database connection and perform auto-migration
func init() {
	config.Connect()
	db = config.GetDB()
	db.AutoMigrate(&User{})
}

func (u *User) CreateUser() *User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err) // Handle error
	}
	u.Password = string(hashedPassword)
	db.Create(&u)
	return u
}

func GetUserByUsername(username string) *User {
	var user User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return nil // User not found
	}
	return &user
}

func GetUserByEmail(email string) *User {
	var user User
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil // User not found
	}
	return &user
}

func (u *User) UpdateUser() *User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		panic(err) // Handle error
	}
	u.Password = string(hashedPassword)
	db.Save(&u)
	return u
}

func DeleteUser(id uint) {
	db.Delete(&User{}, id)
}

// LoginUser checks if the provided username and password match any user in the database
func LoginUser(username, password string) (*User, error) {
	// Retrieve the user from the database by username
	user := GetUserByUsername(username)
	if user == nil {
		return nil, errors.New("user not found")
	}

	// Compare hashed passwords
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, errors.New("password incorrect")
	}

	// Login successful
	return user, nil

}
