package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"to-do-list/pkg/models"
	"to-do-list/pkg/utils"

	"github.com/dgrijalva/jwt-go"

	"github.com/gorilla/mux"
)

// creates a new task for a user
func CreateTask(w http.ResponseWriter, r *http.Request) {
	tokenHeader := r.Header.Get("Authorization") // Extract the token from the request headers
	if tokenHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "Missing authorization header")
		return
	}
	tokenString := strings.Replace(tokenHeader, "Bearer ", "", 1) // Remove the "Bearer " prefix from the token string
	username, err := verifyToken(tokenString)                     // Verify the token and extract the username
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid token: %v", err)
		return
	}

	user := models.GetUserByUsername(username) // Retrieve the user from the database by username
	if user == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Parse the task from the request body
	task := &models.Task{}
	utils.ParseBody(r, task)

	createdTask := models.CreateTask(*task) // Create the task for the user

	res, _ := json.Marshal(createdTask) // Marshal the created task into JSON

	w.Header().Set("Content-Type", "application/json") // Set the response headers
	w.WriteHeader(http.StatusCreated)
	w.Write(res)
}

// retrieves all tasks for the user associated with the provided token
func GetTasks(w http.ResponseWriter, r *http.Request) {

	tokenHeader := r.Header.Get("Authorization")
	if tokenHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tokenString := strings.Replace(tokenHeader, "Bearer ", "", 1)

	username, err := verifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid token: %v", err)
		return
	}

	tasks := models.GetTasks(username)

	res, err := json.Marshal(tasks)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(res)
}

// deletes a task for a user
func DeleteTask(w http.ResponseWriter, r *http.Request) {

	tokenHeader := r.Header.Get("Authorization")
	if tokenHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tokenString := strings.Replace(tokenHeader, "Bearer ", "", 1)

	username, err := verifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid token: %v", err)
		return
	}

	vars := mux.Vars(r)
	taskID := vars["taskID"]

	if !models.DeleteTask(username, taskID) {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// updates a task for a user
func UpdateTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	taskID := vars["taskID"]

	tokenHeader := r.Header.Get("Authorization")
	if tokenHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	tokenString := strings.Replace(tokenHeader, "Bearer ", "", 1)

	username, err := verifyToken(tokenString)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Invalid token: %v", err)
		return
	}

	// Retrieve all tasks for the user
	tasks := models.GetTasks(username)

	// Find the task with the provided taskID
	var taskToUpdate *models.Task
	for _, task := range tasks {
		if strconv.Itoa(int(task.ID)) == taskID {
			taskToUpdate = &task
			break
		}
	}

	// Check if the task exists and belongs to the user
	if taskToUpdate == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Parse the updated task from the request body
	updatedTask := &models.Task{}
	utils.ParseBody(r, updatedTask)

	// Update the task
	if models.UpdateTask(username, taskID, *updatedTask) == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// parses the JWT token and returns its claims
func ParseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte("secretkey"), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
