package main

import (
	"context"
	"flag"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jiaw1/sport-matchmaking-auth-service/auth"
	"github.com/jiaw1/sport-matchmaking-auth-service/handler"
	"github.com/jiaw1/sport-matchmaking-auth-service/log"
	"github.com/jiaw1/sport-matchmaking-auth-service/router"
)

var port = flag.Int("port", 8080, "Server port")

func main() {
	// Parse port flag
	flag.Parse()

	// Create GoCloak client
	goCloakClient := auth.NewGoCloakClient()

	// Initialize OIDC provider
	oidcProvider, err := auth.NewOIDCProvider()
	if err != nil {
		stdlog.Fatalf("Failed to initialize OIDC provider: %s", err.Error())
	}

	// Create router and handler
	r := router.New()
	g := r.Group("")
	h := handler.New(goCloakClient, oidcProvider)

	// Register routes to router main group
	h.RegisterRoutes(g)

	// Prepare for graceful shutdown
	go listenForShutdownSignal(func() {
		r.Shutdown(context.Background())
	})

	// Start the server
	err = r.Start(fmt.Sprintf(":%d", *port))
	if err != http.ErrServerClosed {
		r.Logger.Fatal(err)
	}
}

// Listens for an `os.Interrupt` or `SIGTERM` signal
// and runs the provided `shutdownAction` when received.
func listenForShutdownSignal(shutdownAction func()) {
	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt, syscall.SIGTERM)
	<-s

	log.Logger.Info("Shutdown signal received, shutting down...")
	shutdownAction()
}
