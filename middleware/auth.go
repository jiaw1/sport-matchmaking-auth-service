package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jiaw1/sport-matchmaking-auth-service/auth"
	"github.com/jiaw1/sport-matchmaking-auth-service/log"
	"github.com/labstack/echo/v4"
)

func AuthMiddleware(client *gocloak.GoCloak) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				fmt.Println("Auth header missing")
				return echo.ErrUnauthorized
			}

			// Extract Bearer token
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				fmt.Println("Auth token missing")
				return echo.ErrUnauthorized
			}

			// Validate token
			ctx := context.Background()

			introspect, err := client.RetrospectToken(ctx, token, auth.ClientID, auth.ClientSecret, auth.Realm)
			if err != nil || !*introspect.Active {
				log.Logger.Warn("Token invalid or introspection failed")
				return echo.ErrUnauthorized
			}

			// Get claims
			_, claims, err := client.DecodeAccessToken(ctx, token, auth.Realm)
			if err != nil {
				log.Logger.Error("Failed to decode access token", slog.String("error", err.Error()))
				return echo.ErrUnauthorized
			}

			// Save user ID to context
			userID, err := claims.GetSubject()
			if err != nil {
				log.Logger.Error("Failed to get token subject", slog.String("error", err.Error()))
				return echo.ErrUnauthorized
			}

			// Check if user ID is empty
			if userID == "" {
				log.Logger.Error("Encountered invalid user ID in subject")
				return echo.ErrUnauthorized
			}
			c.Set("user", userID)

			return next(c)
		}
	}
}

func AuthMiddlewareOIDC(verifier *oidc.IDTokenVerifier) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				fmt.Println("Authorization header missing")
				return echo.ErrUnauthorized
			}

			// Extract Bearer token
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				fmt.Println("Auth token missing")
				return echo.ErrUnauthorized
			}

			// Validate token
			ctx := context.Background()

			idToken, err := verifier.Verify(ctx, token)
			if err != nil {
				log.Logger.Warn("Invalid token", slog.String("error", err.Error()))
				return echo.ErrUnauthorized
			}

			// Save user ID to context
			userID := idToken.Subject

			// Check if user ID is empty
			if userID == "" {
				log.Logger.Error("Encountered invalid user ID in subject")
				return echo.ErrUnauthorized
			}
			c.Set("user", userID)

			return next(c)
		}
	}
}
