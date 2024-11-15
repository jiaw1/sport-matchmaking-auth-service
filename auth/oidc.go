package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

func NewOIDCProvider() (provider *oidc.Provider, err error) {
	provider, err = oidc.NewProvider(
		context.Background(),
		fmt.Sprintf("%s/realms/%s", KeycloakURL, Realm),
	)
	return provider, err
}

func GetOIDCVerifierConfig() *oidc.Config {
	return &oidc.Config{
		ClientID: ClientID,
	}
}
