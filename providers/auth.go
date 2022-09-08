package providers

import (
	"net/http"

	"github.com/atonyba/go-authentication/config"
)

type AuthImpl interface {
	Verify(w http.ResponseWriter, r *http.Request)
	Begin(w http.ResponseWriter, r *http.Request)
	Complete(w http.ResponseWriter, r *http.Request)
	Initialize(globalConfig *config.GlobalConfig)
}
