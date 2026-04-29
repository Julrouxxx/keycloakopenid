package keycloakopenid

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// JWKS structures
type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWT structures
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtClaims map[string]interface{}

// Cache pour les clés JWKS
var (
	jwksCache     = make(map[string]*jwks)
	jwksCacheMu   sync.RWMutex
	jwksCacheTime = make(map[string]time.Time)
)

func (k *keycloakAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("Authorization")
	header, headerOk := req.Header["Authorization"]
	headerHasBearer := headerOk && len(header) > 0 && strings.HasPrefix(header[0], "Bearer ")
	if (err == nil && strings.HasPrefix(cookie.Value, "Bearer ")) || headerHasBearer {
		var token string
		if err == nil && strings.HasPrefix(cookie.Value, "Bearer "){
			token = strings.TrimPrefix(cookie.Value, "Bearer ")
			fmt.Printf("login via cookie\n")
		} else if headerHasBearer {
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

// base64URLDecode décode une chaîne base64url (sans padding)
func base64URLDecode(s string) ([]byte, error) {
	// Ajouter le padding manquant
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// parseJWT parse un token JWT et retourne le header, les claims et la signature
func parseJWT(tokenString string) (*jwtHeader, jwtClaims, []byte, string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, nil, nil, "", errors.New("invalid token format")
	}

	// Décoder le header
	headerBytes, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid header JSON: %w", err)
	}

	// Décoder les claims
	claimsBytes, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid claims: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid claims JSON: %w", err)
	}

	// Décoder la signature
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("invalid signature: %w", err)
	}

	// La partie signée est header.payload
	signingInput := parts[0] + "." + parts[1]

	return &header, claims, signature, signingInput, nil
}

// fetchJWKS récupère les clés JWKS depuis Keycloak avec mise en cache
func fetchJWKS(jwksURL string) (*jwks, error) {
	jwksCacheMu.RLock()
	cached, exists := jwksCache[jwksURL]
	cacheTime, timeExists := jwksCacheTime[jwksURL]
	jwksCacheMu.RUnlock()

	// Utiliser le cache s'il est valide (moins d'une heure)
	if exists && timeExists && time.Since(cacheTime) < time.Hour {
		return cached, nil
	}

	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var keys jwks
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Mettre en cache
	jwksCacheMu.Lock()
	jwksCache[jwksURL] = &keys
	jwksCacheTime[jwksURL] = time.Now()
	jwksCacheMu.Unlock()

	return &keys, nil
}

// getPublicKey construit une clé RSA publique depuis un JWK
func getPublicKey(key *jwk) (*rsa.PublicKey, error) {
	if key.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
	}

	// Décoder N (modulus)
	nBytes, err := base64URLDecode(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Décoder E (exponent)
	eBytes, err := base64URLDecode(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}
	// Convertir l'exposant en int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// verifyRS256 vérifie une signature RS256
func verifyRS256(publicKey *rsa.PublicKey, signingInput string, signature []byte) error {
	hash := sha256.Sum256([]byte(signingInput))
	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
}

func (k *keycloakAuth) verifyToken(tokenString string) (bool, error) {
	// Parser le JWT
	header, claims, signature, signingInput, err := parseJWT(tokenString)
	if err != nil {
		return false, nil
	}

	// Vérifier l'algorithme
	if header.Alg != "RS256" {
		return false, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Récupérer les clés JWKS
	jwksURL := k.KeycloakURL.JoinPath(
		"realms",
		k.KeycloakRealm,
		"protocol",
		"openid-connect",
		"certs",
	)

	keys, err := fetchJWKS(jwksURL.String())
	if err != nil {
		return false, err
	}

	// Trouver la clé correspondante
	var matchingKey *jwk
	for i := range keys.Keys {
		if keys.Keys[i].Kid == header.Kid {
			matchingKey = &keys.Keys[i]
			break
		}
	}
	if matchingKey == nil {
		return false, errors.New("no matching key found in JWKS")
	}

	// Construire la clé publique
	publicKey, err := getPublicKey(matchingKey)
	if err != nil {
		return false, err
	}

	// Vérifier la signature
	if err := verifyRS256(publicKey, signingInput, signature); err != nil {
		return false, nil // Signature invalide
	}

	// Vérifier l'expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return false, nil // Token expiré
		}
	} else {
		return false, nil // Pas de claim exp
	}

	// Vérifier l'issuer
	expectedIssuer := fmt.Sprintf("%s/realms/%s", k.KeycloakURL, k.KeycloakRealm)
	if claims["iss"] != expectedIssuer {
		fmt.Printf("issuer mismatch: expected %s, got %s\n", expectedIssuer, claims["iss"])
		return false, nil
	}

	// Vérifier l'audience ou azp (authorized party)
	// En OpenID Connect, azp contient le client_id du client qui a demandé le token
	// aud peut contenir d'autres ressources/services
	audValid := false

	// Vérifier d'abord azp (authorized party)
	if azp, ok := claims["azp"].(string); ok && azp == k.ClientID {
		audValid = true
	}

	// Si pas trouvé dans azp, vérifier aud
	if !audValid {
		aud := claims["aud"]
		switch v := aud.(type) {
		case string:
			if v == k.ClientID {
				audValid = true
			}
		case []interface{}:
			for _, a := range v {
				if a.(string) == k.ClientID {
					audValid = true
					break
				}
			}
		}
	}

	if !audValid {
		fmt.Printf("audience/azp mismatch: expected %s\n", k.ClientID)
		return false, nil
	}

	// Vérifier le rôle si configuré
	if k.KeycloakRole != "" {
		realmAccess, ok := claims["realm_access"].(map[string]interface{})
		if !ok {
			return false, errors.New("NOT_GOOD_ROLE")
		}
		roles, ok := realmAccess["roles"].([]interface{})
		if !ok {
			return false, errors.New("NOT_GOOD_ROLE")
		}
		found := false
		for _, r := range roles {
			if r.(string) == k.KeycloakRole {
				found = true
				break
			}
		}
		if !found {
			return false, errors.New("NOT_GOOD_ROLE")
		}
	}

	return true, nil
}
