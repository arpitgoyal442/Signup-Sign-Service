package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/arpit/signup_in_auth_microservice/pkg/config"
	"github.com/arpit/signup_in_auth_microservice/pkg/models"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Email string             `bson:"email"`
	Password    string             `bson:"password"`
	// Add other fields as needed
}

type token struct{

	Value string `json:"value"`



}

var jwtKey = []byte(os.Getenv("SECRET_KEY"))

func helper_generateJWTToken(userID string) (string, error) {
	// Create the claims for the token
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
		Id:        userID,
	}

	// Create the token with the claims and signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate the signed token string
	signedToken, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func helper_verifyJWTToken(tokenString string) (*jwt.Token, error) {

	// Parse the token string and validate the signature
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the secret key for validation
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}


func helper(w http.ResponseWriter, r *http.Request) (string, string, *mongo.Collection) {
	client := config.GetClient()
	collection := client.Database("mydb").Collection("users")

	var u models.User

	json.NewDecoder(r.Body).Decode(&u)
	fmt.Println(u)

	_, err := json.Marshal(u)
	if err != nil {
		panic(err)
	}

	return u.Email, u.Password, collection

}

func hashPassword(password string) (string, error) {

	// Generate a bcrypt hash of the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Convert the hashed password to a string for storage
	hashedPasswordStr := string(hashedPassword)

	return hashedPasswordStr, nil
}

func verifyPassword(hashedPassword, password string) error {
	// Compare the hashed password with the provided password
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return err
	}

	return nil
}

// func Getjwt(w http.ResponseWriter, r *http.Request){

	
//         data,_:=ioutil.ReadAll(r.Body)
// 		var user models.User

// 		json.Unmarshal(data,&user)
// 		fmt.Println(user.Email)

// 		token,err:=helper_generateJWTToken(user.Email)

// 		if err!=nil{

// 			fmt.Println(err)
// 		}

// 		fmt.Fprintf(w,"token is %v",token)

	
// }
func Parsejwt(w http.ResponseWriter, r *http.Request){

	data,_:=ioutil.ReadAll(r.Body)
		var token token

		json.Unmarshal(data,&token)
		fmt.Println(token.Value)

		v,err:=helper_verifyJWTToken(token.Value)

		if err!=nil{
			fmt.Println(err)
		}

		claims:=v.Claims.(jwt.MapClaims)

		

		user_email:=claims["jti"].(string)

		w.Write([]byte(user_email))

		// fmt.Fprintf(w,"Verified %v ",v)

}

func Signin(w http.ResponseWriter, r *http.Request) {

	email, password, collection := helper(w, r)

	filter := bson.M{
		"email": email,
	}

	result := collection.FindOne(context.Background(), filter)



	var u User
	result.Decode(&u)
	fmt.Println(u.ID.Hex())
	// fmt.Println(u.Password)

	w.Header().Set("Content-Type", "application/json")

	if result.Err() == mongo.ErrNoDocuments {

		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "Login UnSuccessfull Email User Don't Exist")
		return

	} else {

		err := verifyPassword(u.Password, password)

		if err != nil {

			// Password is not Correct
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Password Verification Failed %v", err)
			return

		} else {
			//  Password is Correct
			w.WriteHeader(http.StatusOK)

			jwttoken,err:=helper_generateJWTToken(u.ID.Hex())

			if(err!=nil){
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, "Couldn't generate jwt token %v", err)
				
			}else{

					type Response struct{

						token string  
						id     string   
					}

					data := map[string]interface{}{
						"token": jwttoken,
						"id":    u.ID.Hex(),
					}
				
					
					jsonData, err := json.Marshal(data)


					if(err!=nil){
						fmt.Fprintf(w, "Internal Server Error %v", err)
						return

					}
					w.Write(jsonData)
					
				}

				

			
			

		}
	}

}

func Signup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	email, password, collection := helper(w, r)

	encrypt_password, err := hashPassword(password)

	if err != nil {

		log.Fatal("Error in Hashing the Password")
		fmt.Fprintf(w, "Couldn't Encrypt the Password ...Error is %v", err)

	}

	newuser := models.User{
		Email:    email,
		Password: encrypt_password,
	}

	//  First Check if this email already exist

	filter := bson.M{
		"email": email,
	}

	check := collection.FindOne(context.Background(), filter)

	if check.Err() != mongo.ErrNoDocuments {

		w.WriteHeader(http.StatusNotAcceptable)
	
		fmt.Fprintf(w, "Email Already in use")
	} else {

		// User doesn't already exist --can safely be inserted into db

		result, err := collection.InsertOne(context.Background(), newuser)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
	
		fmt.Fprintf(w, "Couldn't Insert %v",err)
			return
		}
          
		
		

		//  Preparng to write Response
		fmt.Println(result.InsertedID)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Allow-Control-Allow-Methods", "POST")
		w.WriteHeader(200)
		w.Write([]byte( result.InsertedID.(primitive.ObjectID).Hex() ))
		// fmt.Fprintf(w, "Inserted with id: %v ", result.InsertedID)
		
	}

}


