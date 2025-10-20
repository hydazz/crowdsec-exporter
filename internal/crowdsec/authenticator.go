package crowdsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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

	AuthToken.machineLogin = cfg.CrowdSec.Login
	AuthToken.machinePasswd = cfg.CrowdSec.Password

	if cfg.CrowdSec.RegistrationToken == "" {
		AuthToken.isRegistered = true
	}
}

func CheckAuth() error {
	AuthToken.mu.Lock()
	defer AuthToken.mu.Unlock()

	slog.Debug("CheckAuth", "isRegistered", AuthToken.isRegistered, "hasRegToken", AuthToken.Config.CrowdSec.RegistrationToken != "", "tokenExpired", AuthToken.Expire.Before(time.Now()))

	if !AuthToken.isRegistered && AuthToken.Config.CrowdSec.RegistrationToken != "" {
		if err := registerMachine(); err != nil {
			return fmt.Errorf("register machine: %w", err)
		}
		AuthToken.Expire = time.Now()
	}

	if AuthToken.Expire.Before(time.Now()) {
		slog.Debug("authenticate", "machineId", AuthToken.machineLogin)
		if err := authenticate(); err != nil {
			return fmt.Errorf("authenticate: %w", err)
		}
	}

	return nil
}

func GetToken() string { return AuthToken.BearerToken }

func authenticate() error {
	payload := struct {
		Machine_id string `json:"machine_id"`
		Password   string `json:"password"`
	}{
		Machine_id: AuthToken.machineLogin,
		Password:   AuthToken.machinePasswd,
	}

	res, body, err := postJSON(AuthToken.Config.CrowdSec.URL+"/v1/watchers/login", payload)
	if err != nil {
		return fmt.Errorf("auth request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("auth failed: status=%d machineId=%s body=%s", res.StatusCode, payload.Machine_id, string(body))
	}

	var tr struct {
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return fmt.Errorf("auth decode: %w", err)
	}

	AuthToken.BearerToken = tr.Token
	AuthToken.Expire = parseExpire(tr.Expire)
	return nil
}

func registerMachine() error {
	machineId := AuthToken.Config.CrowdSec.Login
	password := AuthToken.Config.CrowdSec.Password

	slog.Debug("checking if machine already exists", "machineId", machineId)
	if tryAuthenticate(machineId, password) {
		slog.Info("machine already registered and accessible", "machineId", machineId)
		AuthToken.isRegistered = true
		return nil
	}

	data := regPayload{
		MachineId:         machineId,
		Password:          password,
		RegistrationToken: AuthToken.Config.CrowdSec.RegistrationToken,
	}

	slog.Debug("attempting registration", "machineId", data.MachineId)
	res, body, err := postJSON(AuthToken.Config.CrowdSec.URL+"/v1/watchers", data)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusCreated || res.StatusCode == http.StatusAccepted {
		slog.Info("successfully registered machine", "machineId", machineId)
		setRegistered(data)
		return nil
	}

	if res.StatusCode == http.StatusForbidden && strings.Contains(string(body), "user already exist") {
		slog.Info("machine already exists, proceeding with provided credentials", "machineId", machineId)
		setRegistered(data)
		return nil
	}

	return fmt.Errorf("registration failed: status=%d body=%s", res.StatusCode, string(body))
}

func tryAuthenticate(machineId, password string) bool {
	payload := struct {
		Machine_id string `json:"machine_id"`
		Password   string `json:"password"`
	}{
		Machine_id: machineId,
		Password:   password,
	}

	res, _, err := postJSON(AuthToken.Config.CrowdSec.URL+"/v1/watchers/login", payload)
	if err != nil {
		return false
	}
	defer res.Body.Close()

	return res.StatusCode == http.StatusOK
}

type regPayload struct {
	MachineId         string `json:"machine_id"`
	Password          string `json:"password"`
	RegistrationToken string `json:"registration_token,omitempty"`
}

func DeregisterMachine() error {
	AuthToken.mu.Lock()
	defer AuthToken.mu.Unlock()

	if !AuthToken.Config.CrowdSec.DeregisterOnExit {
		slog.Debug("deregistration disabled")
		return nil
	}

	if !AuthToken.isRegistered || AuthToken.machineLogin == "" {
		return nil
	}
	if AuthToken.Expire.Before(time.Now()) {
		if err := authenticate(); err != nil {
			return err
		}
	}

	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/v1/watchers/%s", AuthToken.Config.CrowdSec.URL, AuthToken.machineLogin), nil)
	if err != nil {
		return fmt.Errorf("deregister request build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+AuthToken.BearerToken)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("deregister request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent {
		slog.Info("deregistered", "machine_id", AuthToken.machineLogin)
		clearRegistration()
		return nil
	}

	body, _ := io.ReadAll(res.Body)
	slog.Warn("deregister failed", "status", res.StatusCode, "machine_id", AuthToken.machineLogin, "body", string(body))
	return nil
}

func postJSON(url string, v any) (*http.Response, []byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	if err != nil {
		return nil, nil, fmt.Errorf("request build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	body, _ := io.ReadAll(res.Body) // callers still own res.Body Close
	return res, body, nil
}

func parseExpire(s string) time.Time {
	if s == "" {
		return time.Now().Add(time.Hour)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		slog.Warn("expire parse", "value", s, "error", err)
		return time.Now().Add(time.Hour)
	}
	return t
}

func setRegistered(p regPayload) {
	AuthToken.machineLogin = p.MachineId
	AuthToken.machinePasswd = p.Password
	AuthToken.isRegistered = true
}

func clearRegistration() {
	AuthToken.isRegistered = false
	AuthToken.machineLogin = ""
	AuthToken.machinePasswd = ""
	AuthToken.BearerToken = ""
	AuthToken.Expire = time.Now()
}
