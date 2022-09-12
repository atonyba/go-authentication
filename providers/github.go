package providers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type githubResponse struct {
	Data struct {
		Viewer struct {
			ID string `json:"id"`
		} `json:"viewer"`
	} `json:"data"`
}

type GitHubProvider struct {
	Config      oauth2.Config
	Connections map[string]string
}

func (auth *GitHubProvider) Initialize() {
	auth.Config = oauth2.Config{
		ClientID:     "69774624318a45cecb8e",
		ClientSecret: "18856b96980d1874304a0d4b58d70d18ca0f7f11",
		Endpoint:     github.Endpoint,
	}
	auth.Connections = make(map[string]string)
}

func (auth *GitHubProvider) Verify(w http.ResponseWriter, r *http.Request) {
	reqToken := r.Header.Get("Authorization")
	splitToken := strings.Split(reqToken, "Bearer")
	if len(splitToken) != 2 {
		http.Error(w, "Bearer token is in incorrect format", http.StatusBadRequest)
		return
	}

	reqToken = strings.TrimSpace(splitToken[1])

	log.Println("Token:", reqToken)
}

func (auth *GitHubProvider) Complete(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	state := r.FormValue("state")

	if state != "0000" {
		http.Error(w, "State is incorrect", http.StatusBadRequest)
		return
	}

	token, err := auth.Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Could not login", http.StatusInternalServerError)
		return
	}
	log.Println("Access Token:", token.AccessToken)
	log.Println("Refresh Token:", token.RefreshToken)
	log.Println("Authorization Header:", r.Header.Get("Authorization"))

	tokenSource := auth.Config.TokenSource(r.Context(), token)
	client := oauth2.NewClient(r.Context(), tokenSource)

	requestBody := strings.NewReader(`{"query": "query{viewer{id}}"}`)
	response, err := client.Post("https://api.github.com/graphql", "application/json", requestBody)
	if err != nil {
		http.Error(w, "Could not get user", http.StatusInternalServerError)
		return
	}
	defer response.Body.Close()

	var ghResponse githubResponse
	err = json.NewDecoder(response.Body).Decode(&ghResponse)
	if err != nil {
		http.Error(w, "Could not convert response", http.StatusInternalServerError)
		return
	}

	githubId := ghResponse.Data.Viewer.ID
	userId, ok := auth.Connections[githubId]
	if !ok {
		// new user, create account
		auth.Connections[githubId] = uuid.New().String()
		userId = auth.Connections[githubId]
	}

	// login to account userId using JWT
	log.Println("User id ", userId)
}

func (auth *GitHubProvider) Begin(w http.ResponseWriter, r *http.Request) {
	redirectUrl := auth.Config.AuthCodeURL("0000")
	log.Println("Redirecting to ", redirectUrl)
	http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
}
