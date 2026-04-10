package keycloakopenid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	KeycloakURL   string `json:"url"`
	KeycloakRealm string `json:"keycloak_realm"`
	ClientID      string `json:"client_id"`
	KeycloakRole  string `json:"keycloak_role"`

	KeycloakURLEnv   string `json:"url_env"`
	KeycloakRealmEnv string `json:"keycloak_realm_env"`
	ClientIDEnv      string `json:"client_id_env"`
}
type keycloakAuth struct {
	next          http.Handler
	KeycloakURL   *url.URL
	KeycloakRealm string
	ClientID      string
	KeycloakRole  string
}

type KeycloakTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type state struct {
	RedirectURL string `json:"redirect_url"`
}

func CreateConfig() *Config {
	return &Config{}
}

func parseUrl(rawUrl string) (*url.URL, error) {
	if rawUrl == "" {
		return nil, errors.New("invalid empty url")
	}
	if !strings.Contains(rawUrl, "://") {
		rawUrl = "https://" + rawUrl
	}
	u, err := url.Parse(rawUrl)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.Scheme, "http") {
		return nil, fmt.Errorf("%v is not a valid scheme", u.Scheme)
	}
	return u, nil
}

func readConfigEnv(config *Config) error {
	if config.KeycloakURLEnv != "" {
		keycloakUrl := os.Getenv(config.KeycloakURLEnv)
		if keycloakUrl == "" {
			return errors.New("KeycloakURLEnv referenced but NOT set")
		}
		config.KeycloakURL = strings.TrimSpace(keycloakUrl)
	}
	if config.ClientIDEnv != "" {
		clientId := os.Getenv(config.ClientIDEnv)
		if clientId == "" {
			return errors.New("ClientIDEnv referenced but NOT set")
		}
		config.ClientID = strings.TrimSpace(clientId)
	}
	if config.KeycloakRealmEnv != "" {
		keycloakRealm := os.Getenv(config.KeycloakRealmEnv)
		if keycloakRealm == "" {
			return errors.New("KeycloakRealmEnv referenced but NOT set")
		}
		config.KeycloakRealm = strings.TrimSpace(keycloakRealm)
	}
	return nil
}

func New(
	uctx context.Context,
	next http.Handler,
	config *Config,
	name string,
) (http.Handler, error) {

	err := readConfigEnv(config)
	if err != nil {
		return nil, err
	}

	if config.KeycloakURL == "" ||
		config.KeycloakRealm == "" ||
		config.ClientID == "" {
		return nil, errors.New("invalid configuration")
	}

	parsedURL, err := parseUrl(config.KeycloakURL)
	if err != nil {
		return nil, err
	}

	return &keycloakAuth{
		next:          next,
		KeycloakURL:   parsedURL,
		KeycloakRealm: config.KeycloakRealm,
		ClientID:      config.ClientID,
		KeycloakRole:  config.KeycloakRole,
	}, nil
}
