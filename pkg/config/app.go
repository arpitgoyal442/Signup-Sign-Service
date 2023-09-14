package config

import (
	"context"
	"os"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var myclient *mongo.Client

func ConnectDb() {

	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(os.Getenv("DB_URL")).SetServerAPIOptions(serverAPI)

	// Create a new client and connect to the server
	client, err := mongo.Connect(context.TODO(), opts)
	if err != nil {
		panic(err)
	}else{
		fmt.Println("Connected ....")
	}

	myclient=client
}

func GetClient() *mongo.Client {
	return myclient
}
