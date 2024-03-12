// user_controller.go

package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"to-do-list/pkg/models"
	"to-do-list/pkg/utils"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var secretKey = []byte("secret-key")

// registers a new user
func RegisterUser(w http.ResponseWriter, r *http.Request) {
	user := &models.User{}
	utils.ParseBody(r, user)
	user.Password = utils.GetHash([]byte(user.Password)) // Hash the password before creating the user
	createdUser := user.CreateUser()
	res, _ := json.Marshal(createdUser)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(res)
}

// logs as an existing user
func LoginUser(w http.ResponseWriter, r *http.Request) {
	credentials := &models.LoginCredentials{}
	utils.ParseBody(r, credentials)

	fmt.Println("Attempting login with username:", credentials.Username) // Log the username

	hashedPassword := utils.GetHash([]byte(credentials.Password)) // Hash the password provided by the user

	user := models.GetUserByUsername(credentials.Username) // Retrieve the user from the database by username
	if user == nil {
		w.WriteHeader(http.StatusUnauthorized) //user not found
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(hashedPassword)); err != nil { // Compare hashed passwords
		// Password incorrect
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString, err := generateToken(user.Username) // token generated after successful login
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error creating token: %v", err)
		return
	}

	response := struct {
		Token string `json:"token"`
	}{
		Token: tokenString,
	}

	res, _ := json.Marshal(response)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

func generateToken(username string) (string, error) {
	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"username": username,
		})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyToken(tokenString string) (string, error) {
	// Verify JWT token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims")
	}

	username := claims["username"].(string)
	return username, nil
}

// updates a user
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userID"]
	_, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		fmt.Println("error while parsing user ID:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	user := models.GetUserByUsername(userID)
	if user == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	userData := &models.User{}
	utils.ParseBody(r, userData)

	user.FirstName = userData.FirstName
	user.LastName = userData.LastName
	user.Email = userData.Email
	user.Username = userData.Username
	user.Password = utils.GetHash([]byte(userData.Password)) // Hash the updated password
	updatedUser := user.UpdateUser()
	res, _ := json.Marshal(updatedUser)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

// deletes a user
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userID"]
	ID, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		fmt.Println("error while parsing user ID:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	models.DeleteUser(uint(ID))
	w.WriteHeader(http.StatusNoContent)
}

// retrieves a user by username
func GetUserByUsername(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	user := models.GetUserByUsername(username) // Retrieve the user from the database

	if user == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	res, err := json.Marshal(user) // Convert the user to JSON format
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json") // write the json response
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}
