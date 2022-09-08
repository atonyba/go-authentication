package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/atonyba/go-authentication/config"
	"github.com/atonyba/go-authentication/providers"
	"github.com/joho/godotenv"
)

const (
	SERVER_PORT = "8080"
)


var authProvider providers.AzureB2CProvider

func main() {
	err := godotenv.Load(".env")
	if err != nil{
		log.Println("No .env file found. Using system environment variables.")
	}

	config := &config.GlobalConfig{
		AuthorizationState: os.Getenv("AUTH_STATE"),
		TenantName:os.Getenv("TENANT_NAME"),
		TenantId:os.Getenv("TENANT_ID"),
		PolicyName:os.Getenv("POLICY_NAME"),
		B2cClientId:os.Getenv("B2C_CLIENTID"),
		B2cClientSecret:os.Getenv("B2C_CLIENTSECRET"),
	}

	authProvider.Initialize(config)

	http.HandleFunc("/", index)
	http.HandleFunc("/oauth/begin", authProvider.Begin)
	http.HandleFunc("/oauth/receive", authProvider.Complete)
	http.HandleFunc("/oauth/verify", authProvider.Verify)

	log.Println("Starting web service on port", SERVER_PORT)
	http.ListenAndServe(fmt.Sprintf(":%s", SERVER_PORT), nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<!DOCTYPE html>
	<html lang="en">
	<head>
		<meta charset="UTF-8"/>
		<title>Document</title>
	</head>
	<body>
		<form action="/oauth/begin" method="post">
			<input type="submit" value="Login via GitHub"/>
		</form>
	</body>
	</html>
	`)
}
