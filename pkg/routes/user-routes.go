package routes

import (
	"to-do-list/pkg/controllers"

	"github.com/gorilla/mux"
)

func RegisterUserRoutes(router *mux.Router) {
	router.HandleFunc("/users", controllers.RegisterUser).Methods("POST")
	router.HandleFunc("/users/{userID}", controllers.UpdateUser).Methods("PUT")
	router.HandleFunc("/users/{userID}", controllers.DeleteUser).Methods("DELETE")
	router.HandleFunc("/users/{username}", controllers.GetUserByUsername).Methods("GET")
	router.HandleFunc("/login", controllers.LoginUser).Methods("POST")
}
