package main

import (
	"log"
	"net/http"
	"to-do-list/pkg/routes"

	_ "github.com/lib/pq"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()

	routes.RegisterTaskRoutes(r)
	routes.RegisterUserRoutes(r)

	http.Handle("/", r)
	log.Fatal(http.ListenAndServe("localhost:9028", r))
}
