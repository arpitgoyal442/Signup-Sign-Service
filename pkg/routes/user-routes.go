package routes

import (
	
	"github.com/gorilla/mux"
	"github.com/arpit/signup_in_auth_microservice/pkg/controllers"
)

func UserRoutes(r *mux.Router){

	r.HandleFunc("/user/signin",controllers.Signin).Methods("POST")
	r.HandleFunc("/user/signup",controllers.Signup).Methods("POST")
	// r.HandleFunc("/getjwt",controllers.Getjwt).Methods("POST")
	r.HandleFunc("/checktoken",controllers.Parsejwt).Methods("POST")

	

}

