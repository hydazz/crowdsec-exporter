package crowdsec

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hydazz/crowdsec-exporter/internal/config"
)

var AuthToken struct {
	mu          sync.Mutex
	Expire      time.Time
	BearerToken string
	Config      *config.Config
}

func InitializeToken(cfg *config.Config) {
	AuthToken.mu.Lock()
	defer AuthToken.mu.Unlock()

	AuthToken.Expire = time.Now()
	AuthToken.BearerToken = ""
	AuthToken.Config = cfg
}

func CheckAuth() {
	AuthToken.mu.Lock()
	defer AuthToken.mu.Unlock()

	if AuthToken.Expire.Before(time.Now()) {
		authenticate()
	}
}

func GetToken() string {
	return AuthToken.BearerToken
}

func authenticate() {

	var credentials struct {
		Machine_id string `json:"machine_id"`
		Password   string `json:"password"`
	}

	credentials.Machine_id = AuthToken.Config.CrowdSec.Login
	credentials.Password = AuthToken.Config.CrowdSec.Password

	credentials_json, err := json.Marshal(credentials)
	if err != nil {
		slog.Error("Failed to marshal credentials", "error", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("POST", AuthToken.Config.CrowdSec.URL+"/v1/watchers/login", bytes.NewBuffer(credentials_json))
	if err != nil {
		slog.Error("Failed to create authentication request", "error", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error("Failed to authenticate with CrowdSec", "error", err)
		os.Exit(1)
	}
	defer res.Body.Close()

	var TokenResponse struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	json.NewDecoder(res.Body).Decode(&TokenResponse)
	AuthToken.BearerToken = TokenResponse.Token

	// Only parse expire time if it's not empty
	if TokenResponse.Expire != "" {
		AuthToken.Expire, err = time.Parse(time.RFC3339, TokenResponse.Expire)
		if err != nil {
			slog.Warn("Could not parse expire time, using fallback", "expire_time", TokenResponse.Expire, "error", err)
			// Set expiry to 1 hour from now as fallback
			AuthToken.Expire = time.Now().Add(1 * time.Hour)
		}
	} else {
		// If no expire time provided, set to 1 hour from now
		AuthToken.Expire = time.Now().Add(1 * time.Hour)
	}
}
