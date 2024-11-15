package handler

import (
	"fmt"
	"net/http"
	"os"

	"github.com/Nerzal/gocloak/v13"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jiaw1/sport-matchmaking-auth-service/auth"
	"github.com/labstack/echo/v4"
)

type Handler struct {
	goCloakClient *gocloak.GoCloak
	oidcProvider  *oidc.Provider
}

func New(goCloakClient *gocloak.GoCloak, oidcProvider *oidc.Provider) *Handler {
	return &Handler{
		goCloakClient: goCloakClient,
		oidcProvider:  oidcProvider,
	}
}

func (h *Handler) RegisterRoutes(g *echo.Group) {

	g.GET("/login", func(c echo.Context) error {
		redirectURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&response_type=code&scope=openid&redirect_uri=%s",
			auth.KeycloakURL, auth.Realm, auth.ClientID, "http://localhost:8080/callback")
		return c.Redirect(http.StatusFound, redirectURL)
	})

	g.GET("/signup", func(c echo.Context) error {
		keycloakURL := os.Getenv("KEYCLOAK_URL")
		realm := os.Getenv("KEYCLOAK_REALM")
		clientID := os.Getenv("KEYCLOAK_CLIENT_ID")
		redirectURI := "http://localhost:8080/callback"

		registrationURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/registrations?client_id=%s&response_type=code&scope=openid&redirect_uri=%s",
			keycloakURL, realm, clientID, redirectURI)

		return c.Redirect(http.StatusFound, registrationURL)
	})

	g.GET("/logout", func(c echo.Context) error {
		keycloakURL := os.Getenv("KEYCLOAK_URL")
		realm := os.Getenv("KEYCLOAK_REALM")
		redirectURI := "http://localhost:8080"

		logoutURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout?redirect_uri=%s",
			keycloakURL, realm, redirectURI)

		return c.Redirect(http.StatusFound, logoutURL)
	})

	g.GET("/callback", func(c echo.Context) error {
		code := c.QueryParam("code")
		if code == "" {
			return c.String(http.StatusBadRequest, "Authorization code not found")
		}

		// Exchange the code for an access token
		token, err := exchangeCodeForToken(code)
		if err != nil {
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Failed to exchange token: %v", err))
		}

		// Print the token
		return c.String(http.StatusOK, fmt.Sprintf("Access token: %s", token))
	})

	g.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "Hello world!")
	})

	// TODO: Remove this endpoint
	g.GET("/test", func(c echo.Context) error {
		username := c.QueryParam("username")
		password := c.QueryParam("password")
		jwt, err := h.goCloakClient.Login(c.Request().Context(), auth.ClientID, auth.ClientSecret, auth.Realm, username, password)
		if err != nil {
			return c.JSON(400, err)
		}
		return c.JSON(http.StatusOK, jwt)
	})
}
