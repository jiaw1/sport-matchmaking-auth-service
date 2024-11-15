package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/jiaw1/sport-matchmaking-auth-service/auth"
)

// Function to exchange authorization code for token
func exchangeCodeForToken(code string) (string, error) {
	tokenEndpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", auth.KeycloakURL, auth.Realm)
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "http://localhost:8080/callback")
	data.Set("client_id", auth.ClientID)
	data.Set("client_secret", auth.ClientSecret)

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected response status: %d, body: %s", resp.StatusCode, body)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	fmt.Printf("Raw response body: %s\n", body) // Debug log

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("failed to parse token response: %v", err)
	}

	return tokenResp.AccessToken, nil
}
