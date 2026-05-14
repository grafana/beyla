package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

func (s *Server) setupWebhookServer(server *http.Server) chan error {
	if s.cfg.Injector.Webhook.UsesExternalWebhook() {
		return nil
	}
	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.ListenAndServeTLS(s.cfg.Injector.Webhook.CertPath, s.cfg.Injector.Webhook.KeyPath); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("webhook server failed: %w", err)
		}
		close(errChan)
	}()
	return errChan
}

func (s *Server) waitForCancellation(ctx context.Context, server *http.Server, errChan chan error) error {
	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Debug("shutting down webhook server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if !s.cfg.Injector.Webhook.UsesExternalWebhook() {
			if err := server.Shutdown(shutdownCtx); err != nil {
				return fmt.Errorf("webhook server shutdown failed: %w", err)
			}
		}
		// Don't return ctx.Err() as an error - graceful shutdown is expected
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil
		}
		return ctx.Err()
	case err := <-errChan:
		if err != nil {
			return err
		}
		return nil
	}
}

// waitForTLSFiles blocks until both TLS cert and key exist or context/timeout expires.
func waitForTLSFiles(ctx context.Context, certPath, keyPath string, timeout, poll time.Duration) error {
	deadline := time.After(timeout)
	for {
		if _, err := os.Stat(certPath); err == nil {
			if _, err := os.Stat(keyPath); err == nil {
				return nil
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return errors.New("TLS files not found before timeout")
		case <-time.After(poll):
		}
	}
}

func (s *Server) ID() string { return uuid.NewString() }
