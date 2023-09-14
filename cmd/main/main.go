package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	

	"github.com/arpit/signup_in_auth_microservice/pkg/config"
	"github.com/arpit/signup_in_auth_microservice/pkg/routes"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"path/filepath"
	"github.com/rs/cors"
	
)


func main(){

	err := godotenv.Load(filepath.Join("D:/NextProject/rentwheelz/Backend/Signup-in-auth Microservice", ".env"))
	if err != nil {
	  log.Fatal("Error loading .env file")
	}

	fmt.Println(os.Getenv("KEY"))
	

	config.ConnectDb();

	r:=mux.NewRouter()
	c := cors.New(cors.Options{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	})
	
	handler:=c.Handler(r)

	

	routes.UserRoutes(r)

	http.Handle("/",r)
	log.Fatal(http.ListenAndServe(":8000", handler))

	fmt.Println("HEllo World")
	
	
}