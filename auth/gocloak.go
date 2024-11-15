package auth

import (
	"fmt"
	"os"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/jiaw1/sport-matchmaking-auth-service/log"
)

var (
	KeycloakURL  = os.Getenv("KEYCLOAK_URL")
	Realm        = os.Getenv("KEYCLOAK_REALM")
	ClientID     = os.Getenv("KEYCLOAK_CLIENT_ID")
	ClientSecret = os.Getenv("KEYCLOAK_CLIENT_SECRET")
)

func NewGoCloakClient() *gocloak.GoCloak {
	if err := checkEnv(); err != nil {
		log.Logger.Error(err.Error())
	}

	return gocloak.NewClient(KeycloakURL)
}

func checkEnv() error {
	missingEnvs := make([]string, 0)
	if KeycloakURL == "" {
		missingEnvs = append(missingEnvs, "KEYCLOAK_URL")
	}
	if Realm == "" {
		missingEnvs = append(missingEnvs, "KEYCLOAK_REALM")
	}
	if ClientID == "" {
		missingEnvs = append(missingEnvs, "KEYCLOAK_CLIENT_ID")
	}
	if ClientSecret == "" {
		missingEnvs = append(missingEnvs, "KEYCLOAK_CLIENT_SECRET")
	}

	if len(missingEnvs) > 0 {
		return fmt.Errorf("the following Keycloak environment variables are undefined: %s", strings.Join(missingEnvs, ", "))
	}

	return nil
}
