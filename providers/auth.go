package providers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/atonyba/go-authentication/config"
	"golang.org/x/oauth2"
)

type AuthImpl interface {
	Verify(w http.ResponseWriter, r *http.Request)
	Begin(w http.ResponseWriter, r *http.Request)
	Complete(w http.ResponseWriter, r *http.Request)
	Initialize(globalConfig *config.GlobalConfig)
}

type OAuthClient struct {
	Config *oauth2.Config
}

var AuthClient OAuthClient

func (a *OAuthClient) Initialize(config *config.GlobalConfig) {
	a.Config = &oauth2.Config{
		ClientID:     config.B2cClientId,
		ClientSecret: config.B2cClientSecret,
		Scopes:       []string{fmt.Sprintf("https://%s.onmicrosoft.com/%s/Account.Read", config.TenantName, config.PolicyName), "openid"},
		RedirectURL:  config.RedirectUri,
		Endpoint:     AzureB2CEndpoint(config.TenantName, config.PolicyName),
	}
}

type AuthorizeRequest struct {
	BaseUrl      string
	ClientId     string
	RedirectUri  string
	ResponseMode string
	ResponseType string
	Scopes       []string
	State        string
}

type TokenRequest struct {
	BaseUrl      string
	ClientId     string
	ClientSecret string
	Code         string
	GrantType    string
	RedirectUri  string
	Scopes       []string
}

type TokenResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	NotBefore             int    `json:"not_before"`
	ExpiresIn             int    `json:"expires_in"`
	ExpiresOn             int    `json:"expires_on"`
	Resource              string `json:"resource"`
	IdToken               string `json:"id_token"`
	IdTokenExpiresIn      int    `json:"id_token_expires_in"`
	ProfileInfo           string `json:"profile_info"`
	Scope                 string `json:"scope"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn string `json:"refresh_token_expires_in"`
}

type OidcConfigurationResponse struct {
	Issuer                   string   `json:"issuer"`
	AuthURL                  string   `json:"authorization_endpoint"`
	TokenURL                 string   `json:"token_endpoint"`
	EndSessionEndpoint       string   `json:"end_session_endpoint"`
	JWKSURL                  string   `json:"jwks_uri"`
	UserInfoURL              string   `json:"userinfo_endpoint"`
	ResponseModes            []string `json:"response_modes_supported"`
	ResponseTypes            []string `json:"response_types_supported"`
	Scopes                   []string `json:"scopes_supported"`
	SubjectTypes             []string `json:"subject_types_supported"`
	Algorithms               []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	Claims                   []string `json:"claims_supported"`
}

func (a *OAuthClient) CreateAuthRedirectUrl(request AuthorizeRequest) string {
	// Build the URL to use to send the client to
	authRedirectUrl := fmt.Sprintf("%s?client_id=%s&response_type=%s&redirect_uri=%s&response_mode=%s&scope=%s&state=%s",
		request.BaseUrl,
		request.ClientId,
		request.ResponseType,
		request.RedirectUri,
		request.ResponseMode,
		strings.Join(request.Scopes, " "),
		request.State)

	return authRedirectUrl
}

func (a *OAuthClient) GetToken(request TokenRequest) (TokenResponse, error) {
	var tokenResponse TokenResponse

	formData := url.Values{
		"client_id":     {request.ClientId},
		"client_secret": {request.ClientSecret},
		"code":          {request.Code},
		"grant_type":    {request.GrantType},
		"redirect_url":  {request.RedirectUri},
		"scope":         request.Scopes,
	}
	log.Println("Form Data:", formData)

	response, err := http.PostForm(request.BaseUrl, formData)
	if err != nil {
		log.Fatalln(err)
	}
	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return tokenResponse, err
	}

	err = json.Unmarshal(responseBody, &tokenResponse)
	if err != nil {
		return tokenResponse, err
	}

	return tokenResponse, err
}

func (a *OAuthClient) GetOidcConfiguration(baseUrl string) {

}
