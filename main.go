package keycloakopenid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)


func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("Authorization")
	header, headerOk := req.Header["Authorization"]
	if (err == nil && strings.HasPrefix(cookie.Value, "Bearer ")) || (headerOk && strings.HasPrefix(header[0], "Bearer ")) {
		var token string;
		if err == nil && strings.HasPrefix(cookie.Value, "Bearer "){
			token = strings.TrimPrefix(cookie.Value, "Bearer ")
			fmt.Printf("login via cookie\n")
		} else if headerOk {
			token = strings.TrimPrefix(header[0], "Bearer ")
			fmt.Printf("login via header\n")
		}

		ok, err := k.verifyToken(token)
		if err != nil {
			if err.Error() == "NOT_GOOD_ROLE" {
				http.Error(rw, "Vous n'avez pas le bon role", http.StatusForbidden)
				return
			}
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if !ok {
			qry := req.URL.Query()
			qry.Del("code")
			qry.Del("state")
			qry.Del("session_state")
			req.URL.RawQuery = qry.Encode()
			req.RequestURI = req.URL.RequestURI()

			expiration := time.Now().Add(-24 * time.Hour)
			newCookie := &http.Cookie{
				Name:    "Authorization",
				Value:   "",
				Path:    "/",
				Expires: expiration,
				MaxAge:  -1,
			}
			http.SetCookie(rw, newCookie)

			k.redirectToKeycloak(rw, req)
			return
		}
		req.Header.Set("Authorization", "Bearer " + token)
		k.next.ServeHTTP(rw, req)
	} else {
		authCode := req.URL.Query().Get("code")
		if authCode == "" {
			fmt.Printf("code is missing, redirect to keycloak\n")
			k.redirectToKeycloak(rw, req)
			return
		}

		stateBase64 := req.URL.Query().Get("state")
		if stateBase64 == "" {
			fmt.Printf("state is missing, redirect to keycloak\n")
			k.redirectToKeycloak(rw, req)
			return
		}

		fmt.Printf("exchange auth code called\n")
		token, err := k.exchangeAuthCode(req, authCode, stateBase64)
		fmt.Printf("exchange auth code finished %+v\n", token)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(rw, &http.Cookie{
			Name:     "Authorization",
			Value:    "Bearer " + token,
			Secure:   true,
			HttpOnly: true,
			Path:     "/",
			SameSite: http.SameSiteStrictMode,
		})

		qry := req.URL.Query()
		qry.Del("code")
		qry.Del("state")
		qry.Del("session_state")
		req.URL.RawQuery = qry.Encode()
		req.RequestURI = req.URL.RequestURI()
		
		scheme := req.Header.Get("X-Forwarded-Proto")
		host := req.Header.Get("X-Forwarded-Host")
		originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)
		req.Header.Set("Authorization", "Bearer " + token)

		http.Redirect(rw, req, originalURL, http.StatusFound)
	}
}

func (k *keycloakAuth) exchangeAuthCode(req *http.Request, authCode string, stateBase64 string) (string, error) {
	stateBytes, _ := base64.StdEncoding.DecodeString(stateBase64)
	var state state
	err := json.Unmarshal(stateBytes, &state)
	if err != nil {
		return "", err
	}

	target := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"token",
	)
	resp, err := http.PostForm(target.String(),
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {k.ClientID},
			"code":          {authCode},
			"redirect_uri":  {state.RedirectURL},
		})

	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", errors.New("received bad response from Keycloak: " + string(body))
	}

	var tokenResponse KeycloakTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.AccessToken, nil
}

func (k *keycloakAuth) redirectToKeycloak(rw http.ResponseWriter, req *http.Request) {
	scheme := req.Header.Get("X-Forwarded-Proto")
	host := req.Header.Get("X-Forwarded-Host")
	originalURL := fmt.Sprintf("%s://%s%s", scheme, host, req.RequestURI)

	state := state{
		RedirectURL: originalURL,
	}

	stateBytes, _ := json.Marshal(state)
	stateBase64 := base64.StdEncoding.EncodeToString(stateBytes)

	redirectURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"auth",
	)
	redirectURL.RawQuery = url.Values{
		"response_type": {"code"},
		"client_id":     {k.ClientID},
		"redirect_uri":  {originalURL},
		"state":         {stateBase64},
	}.Encode()

	http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
}


func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}
func (k *keycloakAuth) verifyToken(tokenString string) (bool, error) {
	jwksURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"certs",
	)

	jwks, err := keyfunc.Get(jwksURL.String(), keyfunc.Options{
		RefreshInterval: time.Hour,
	})
	if err != nil {
		return false, err
	}

	token, err := jwt.Parse(tokenString, jwks.Keyfunc)
	if err != nil || !token.Valid {
		return false, nil
	}

	claims := token.Claims.(jwt.MapClaims)

	// issuer
	if claims["iss"] != fmt.Sprintf("%s/realms/%s", k.KeycloakURL, k.KeycloakRealm) {
		return false, nil
	}

	// audience
	aud := claims["aud"]
	if aud != k.ClientID {
		return false, nil
	}

	// rôle
	if k.KeycloakRole != "" {
		realmAccess := claims["realm_access"].(map[string]interface{})
		roles := realmAccess["roles"].([]interface{})
		found := false
		for _, r := range roles {
			if r.(string) == k.KeycloakRole {
				found = true
			}
		}
		if !found {
			return false, errors.New("NOT_GOOD_ROLE")
		}
	}

	return true, nil
}
