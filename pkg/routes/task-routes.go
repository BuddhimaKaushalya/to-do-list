package routes

import (
	"to-do-list/pkg/controllers"

	"github.com/gorilla/mux"
)

func RegisterTaskRoutes(router *mux.Router) {
	router.HandleFunc("/users/tasks", controllers.CreateTask).Methods("POST")
	router.HandleFunc("/tasks", controllers.GetTasks).Methods("GET")
	router.HandleFunc("/tasks/{taskID}", controllers.DeleteTask).Methods("DELETE")
	router.HandleFunc("/users/tasks/{taskID}", controllers.UpdateTask).Methods("PUT")
}
