package providers

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/atonyba/go-authentication/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type AzureB2CProvider struct {
	OAuthConfig    oauth2.Config
	Connections    map[string]string
	ConfigSettings *config.GlobalConfig
}

type jwtSigningKeys struct {
	Keys []jwtSigningKey `json:"keys"`
}

type jwtSigningKey struct {
	KeyId     string `json:"kid"`
	NotBefore string `json:"nbf"`
	Usage     string `json:"use"`
	KeyType   string `json:"kty"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
	PublicKey rsa.PublicKey
}

func AzureB2CEndpoint(tenant string, policyName string) oauth2.Endpoint {
	if tenant == "" {
		tenant = "common"
	}
	return oauth2.Endpoint{
		AuthURL:  getBaseEndpointUrl(tenant, policyName) + "/authorize",
		TokenURL: getBaseEndpointUrl(tenant, policyName) + "/token",
	}
}

func (auth *AzureB2CProvider) Initialize(globalConfig *config.GlobalConfig) {
	auth.OAuthConfig = oauth2.Config{
		ClientID:     globalConfig.B2cClientId,
		ClientSecret: globalConfig.B2cClientSecret,
		Scopes:       []string{fmt.Sprintf("https://%s.onmicrosoft.com/%s/Account.Read", globalConfig.TenantName, globalConfig.PolicyName), oidc.ScopeOpenID},
		RedirectURL:  "http://localhost:8080/oauth/receive",
		Endpoint:     AzureB2CEndpoint(globalConfig.TenantName, globalConfig.PolicyName),
	}
	auth.Connections = make(map[string]string)
	auth.ConfigSettings = globalConfig
}

func (auth *AzureB2CProvider) Begin(w http.ResponseWriter, r *http.Request) {
	redirectUrl := auth.OAuthConfig.AuthCodeURL(auth.ConfigSettings.AuthorizationState)
	log.Println("Redirecting to ", redirectUrl)
	http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
}

func (auth *AzureB2CProvider) Complete(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	log.Println("Code:", code)

	state := r.FormValue("state")
	log.Println("State:", state)

	if state != auth.ConfigSettings.AuthorizationState {
		http.Error(w, "State is incorrect", http.StatusBadRequest)
		return
	}

	authCodeOptions := oauth2.SetAuthURLParam("response_type", "code id_token")

	token, err := auth.OAuthConfig.Exchange(r.Context(), code, authCodeOptions)
	if err != nil {
		log.Println("Error during token exchange:", err)
		http.Error(w, "Could not login", http.StatusInternalServerError)
		return
	}
	log.Println("Valid:", token.Valid())
	log.Println("Access Token:", token.AccessToken)

	tokenSource := auth.OAuthConfig.TokenSource(r.Context(), token)
	log.Println("Token Source:", tokenSource)
}

func (auth *AzureB2CProvider) Verify(w http.ResponseWriter, r *http.Request) {
	reqToken, err := getTokenString(r)
	if err != nil {
		log.Println("Error when extracting token from request", err)
		http.Error(w, "Could not get token for validation", http.StatusBadRequest)
	}
	log.Println("reqToken:", reqToken)

	w.Write([]byte(reqToken))

	signingKeys, err := getKeyData(auth.ConfigSettings.TenantName, auth.ConfigSettings.PolicyName)
	if err != nil {
		log.Println("Error when retrieving signing keys", err)
		http.Error(w, "Could not get signing keys for validation", http.StatusBadRequest)
	}
	parseJwt(reqToken, signingKeys)
}

// getTokenString scans the request for a bearer token and returns only the token.
//
// This API assumes that the bearer token is in a request header called Authorization.
func getTokenString(r *http.Request) (string, error) {
	reqToken := r.Header.Get("Authorization")
	fmt.Printf("%+v\n", reqToken)
	splitToken := strings.Split(reqToken, "Bearer")
	if len(splitToken) != 2 {
		log.Println("Something went wrong with extracting the token")
		return "", errors.New("something went wrong with extracting the token")
	}

	reqToken = strings.TrimSpace(splitToken[1]) //I don't want the word Bearer.
	return reqToken, nil
}

func getKeyData(tenant string, policy string) (jwtSigningKeys, error) {
	var signingKeys jwtSigningKeys

	log.Println("keys URL:", fmt.Sprintf("%s/discovery/v2.0/keys", getProviderUrl(tenant, policy)))
	response, err := http.Get(fmt.Sprintf("%s/discovery/v2.0/keys", getProviderUrl(tenant, policy)))
	if err != nil {
		return signingKeys, err
	}

	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&signingKeys)
	if err != nil {
		return signingKeys, err
	}

	return signingKeys, nil
}

func getProviderUrl(tenant string, policyName string) string {
	return fmt.Sprintf("https://%s.b2clogin.com/%s.onmicrosoft.com/%s", tenant, tenant, policyName)
}

func getBaseEndpointUrl(tenant string, policyName string) string {
	return "https://" + tenant + ".b2clogin.com/" + tenant + ".onmicrosoft.com/" + policyName + "/oauth2/v2.0"
}
