package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/atonyba/go-authentication/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type AzureB2CProvider struct {
	OAuthConfig    oauth2.Config
	ConfigSettings *config.GlobalConfig
}

type jwtSigningKeys struct {
	Keys []jwtSigningKey `json:"keys"`
}

type jwtSigningKey struct {
	KeyId       string `json:"kid"`
	NotBefore   int    `json:"nbf"`
	Usage       string `json:"use"`
	KeyType     string `json:"kty"`
	Exponent    string `json:"e"`
	Modulus     string `json:"n"`
	precomputed interface{}
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
		Scopes:       []string{fmt.Sprintf("https://%s.onmicrosoft.com/%s/Account.Read", globalConfig.TenantName, globalConfig.B2cClientId), oidc.ScopeOpenID},
		RedirectURL:  "http://localhost:8080/oauth/receive",
		Endpoint:     AzureB2CEndpoint(globalConfig.TenantName, globalConfig.PolicyName),
	}
	auth.ConfigSettings = globalConfig

	// Initialize the custom oauth2 client
	AuthClient.Initialize(globalConfig)
}

func (auth *AzureB2CProvider) Begin(w http.ResponseWriter, r *http.Request) {
	authorizeRequest := &AuthorizeRequest{
		BaseUrl:      auth.OAuthConfig.Endpoint.AuthURL,
		ClientId:     auth.OAuthConfig.ClientID,
		ResponseType: "code", // always enforce the authorization_code flow of oauth2
		RedirectUri:  auth.OAuthConfig.RedirectURL,
		ResponseMode: "form_post",
		Scopes:       auth.OAuthConfig.Scopes,
		State:        uuid.New().String(),
	}

	redirectUrl := AuthClient.CreateAuthRedirectUrl(*authorizeRequest)
	log.Println("Redirecting to ", redirectUrl)
	http.Redirect(w, r, redirectUrl, http.StatusSeeOther)
}

func (auth *AzureB2CProvider) Complete(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	log.Println("Code:", code)

	state := r.FormValue("state")
	log.Println("State:", state)

	// if state != auth.ConfigSettings.AuthorizationState {
	// 	http.Error(w, "State is incorrect", http.StatusBadRequest)
	// 	return
	// }

	tokenRequest := &TokenRequest{
		BaseUrl:      auth.OAuthConfig.Endpoint.TokenURL,
		ClientId:     auth.OAuthConfig.ClientID,
		ClientSecret: auth.OAuthConfig.ClientSecret,
		Code:         code,
		GrantType:    "authorization_code",
		RedirectUri:  auth.OAuthConfig.RedirectURL,
		Scopes:       []string{auth.OAuthConfig.ClientID}, //, "openid"
	}

	tokenResponse, err := AuthClient.GetToken(*tokenRequest)
	if err != nil {
		http.Error(w, "failed to retrieve token from IDP", http.StatusBadRequest)
		return
	}

	log.Println("Access Token:", tokenResponse.AccessToken)
}

func (auth *AzureB2CProvider) Verify(w http.ResponseWriter, r *http.Request) {
	reqToken, err := getTokenString(r)
	if err != nil {
		log.Println("Error when extracting token from request", err)
		http.Error(w, "Could not get token for validation", http.StatusBadRequest)
	}
	log.Println("reqToken:", reqToken)

	oidcConfig, err := getOidcConfiguration(getOidcConfigurationUrl(auth.ConfigSettings.TenantName, auth.ConfigSettings.PolicyName))
	if err != nil {
		log.Println("Could not get the oidc configuration from the service")
		http.Error(w, "Issues reaching the validation data", http.StatusBadRequest)
	}

	signingKeys, err := getKeyData(oidcConfig.JWKSURL)
	if err != nil {
		log.Println("Error when retrieving signing keys", err)
		http.Error(w, "Could not get signing keys for validation", http.StatusBadRequest)
	}
	parseJwt(reqToken, signingKeys)
}

func getBaseEndpointUrl(tenant string, policyName string) string {
	return fmt.Sprintf("%s/oauth2/v2.0", getProviderUrl(tenant, policyName))
}

func getKeyData(keyUrl string) (jwtSigningKeys, error) {
	var signingKeys jwtSigningKeys

	log.Println("keys URL:", keyUrl)
	response, err := http.Get(keyUrl)
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

// get OidcConfiguration returns the json document that describes the oidc configuration for the identity provider
func getOidcConfiguration(configUrl string) (OidcConfigurationResponse, error) {
	var oidcConfig OidcConfigurationResponse

	response, err := http.Get(configUrl)
	if err != nil {
		return oidcConfig, err
	}

	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&oidcConfig)
	if err != nil {
		return oidcConfig, err
	}

	return oidcConfig, nil
}

// get OidcConfigurationUrl returns the url to the OIDC configuration page where token validation data can be found.
func getOidcConfigurationUrl(tenant string, policyName string) string {
	return fmt.Sprintf("%s/v2.0/.well-known/openid-configuration", getProviderUrl(tenant, policyName))
}

// get getProviderUrl returns the base URL that other oauth2 urls are build upon. For Azure B2C, the format returned
// is https://(tenant).b2clogin.com/(tenant).onmicrosoft.com/(policyName)
//
// Note: the return value does not include a trailing slash.
func getProviderUrl(tenant string, policyName string) string {
	return fmt.Sprintf("https://%s.b2clogin.com/%s.onmicrosoft.com/%s", tenant, tenant, policyName)
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
