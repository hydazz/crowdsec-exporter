package crowdsec

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/hydazz/crowdsec-exporter/internal/config"
)

var AuthToken struct {
	mu            sync.Mutex
	Expire        time.Time
	BearerToken   string
	Config        *config.Config
	isRegistered  bool
	machineLogin  string
	machinePasswd string
}

func InitializeToken(cfg *config.Config) {
	AuthToken.mu.Lock()
	defer AuthToken.mu.Unlock()

	AuthToken.Expire = time.Now()
	AuthToken.BearerToken = ""
	AuthToken.Config = cfg
	AuthToken.isRegistered = false

	// If using login/password auth, we're already "registered"
	if cfg.CrowdSec.Login != "" && cfg.CrowdSec.Password != "" {
		AuthToken.isRegistered = true
		AuthToken.machineLogin = cfg.CrowdSec.Login
		AuthToken.machinePasswd = cfg.CrowdSec.Password
	}
}

func CheckAuth() {
	AuthToken.mu.Lock()
	defer AuthToken.mu.Unlock()

	slog.Debug("CheckAuth called", "isRegistered", AuthToken.isRegistered, "hasRegistrationToken", AuthToken.Config.CrowdSec.RegistrationToken != "", "tokenExpired", AuthToken.Expire.Before(time.Now()))

	// If using auto-registration and not yet registered, register first
	if !AuthToken.isRegistered && AuthToken.Config.CrowdSec.RegistrationToken != "" {
		slog.Debug("Attempting to register machine")
		if err := registerMachine(); err != nil {
			slog.Error("Failed to register machine", "error", err)
			os.Exit(1)
		}
		// After successful registration, we need to authenticate to get a token
		// Reset the expiry to force authentication
		AuthToken.Expire = time.Now()
	}

	if AuthToken.Expire.Before(time.Now()) {
		slog.Debug("Token expired, authenticating", "machineId", AuthToken.machineLogin)
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

	credentials.Machine_id = AuthToken.machineLogin
	credentials.Password = AuthToken.machinePasswd

	slog.Debug("Authenticating with credentials", "machineId", credentials.Machine_id)

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

	if res.StatusCode != http.StatusOK {
		slog.Error("Authentication failed", "status", res.StatusCode, "machineId", credentials.Machine_id)
		os.Exit(1)
	}

	var TokenResponse struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	if err := json.NewDecoder(res.Body).Decode(&TokenResponse); err != nil {
		slog.Error("Failed to decode authentication response", "error", err)
		os.Exit(1)
	}

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

func registerMachine() error {
	machineName := AuthToken.Config.CrowdSec.MachineName
	if machineName == "" {
		// Use hostname as default machine name
		hostname, err := os.Hostname()
		if err != nil {
			machineName = "crowdsec-exporter"
		} else {
			machineName = fmt.Sprintf("crowdsec-exporter-%s", hostname)
		}
	}

	registerData := struct {
		MachineId         string `json:"machine_id"`
		Password          string `json:"password"`
		RegistrationToken string `json:"registration_token,omitempty"`
	}{
		MachineId:         machineName,
		Password:          generatePassword(),
		RegistrationToken: AuthToken.Config.CrowdSec.RegistrationToken,
	}

	slog.Debug("Registering machine", "machineId", registerData.MachineId, "url", AuthToken.Config.CrowdSec.URL+"/v1/watchers")

	registerJSON, err := json.Marshal(registerData)
	if err != nil {
		return fmt.Errorf("failed to marshal registration data: %w", err)
	}

	req, err := http.NewRequest("POST", AuthToken.Config.CrowdSec.URL+"/v1/watchers", bytes.NewBuffer(registerJSON))
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to register with CrowdSec: %w", err)
	}
	defer res.Body.Close()

	slog.Debug("Registration response", "status", res.StatusCode, "machineId", registerData.MachineId)

	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusAccepted {
		// Log response body for debugging
		bodyBytes := make([]byte, 0)
		if res.Body != nil {
			bodyBytes, _ = io.ReadAll(res.Body)
		}
		slog.Error("Registration failed", "status", res.StatusCode, "machineId", registerData.MachineId, "responseBody", string(bodyBytes))
		return fmt.Errorf("registration failed with status: %d", res.StatusCode)
	}

	// Registration successful, store credentials
	AuthToken.machineLogin = registerData.MachineId
	AuthToken.machinePasswd = registerData.Password
	AuthToken.isRegistered = true

	slog.Info("Successfully registered machine", "machine_id", registerData.MachineId)
	return nil
}

func generatePassword() string {
	// Generate a cryptographically secure random password
	randomBytes := make([]byte, 16)
	if _, err := cryptorand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based password if crypto/rand fails
		return fmt.Sprintf("exporter-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(randomBytes)
}
