package webhook

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// Server represents the webhook server
type Server struct {
	Port     int
	CertPath string
	KeyPath  string
	mutator  *PodMutator
	logger   *slog.Logger
	server   *http.Server
}

// Config holds the webhook server configuration
type Config struct {
	Port     int
	CertPath string
	KeyPath  string
}

// NewServer creates a new webhook server
func NewServer(cfg Config) *Server {
	return &Server{
		Port:     cfg.Port,
		CertPath: cfg.CertPath,
		KeyPath:  cfg.KeyPath,
		mutator:  NewPodMutator(),
		logger:   slog.Default().With("component", "webhook-server"),
	}
}

// Start starts the webhook server
func (s *Server) Start(ctx context.Context) error {
	if err := waitForTLSFiles(ctx, s.CertPath, s.KeyPath, 30*time.Second, time.Second); err != nil {
		return fmt.Errorf("webhook tls not ready: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", s.mutator.HandleMutate)
	mux.HandleFunc("/health", s.mutator.HealthCheck)
	mux.HandleFunc("/readyz", s.mutator.HealthCheck)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Load TLS certificates
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	s.server.TLSConfig = tlsConfig

	s.logger.Info("starting webhook server", "port", s.Port, "certPath", s.CertPath)

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServeTLS(s.CertPath, s.KeyPath); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("webhook server failed: %w", err)
		}
		close(errChan)
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("shutting down webhook server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("webhook server shutdown failed: %w", err)
		}
		return ctx.Err()
	case err := <-errChan:
		if err != nil {
			return err
		}
		return nil
	}
}

// Stop gracefully stops the webhook server
func (s *Server) Stop(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	s.logger.Info("stopping webhook server")
	return s.server.Shutdown(ctx)
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
			return errors.New("tls files not found before timeout")
		case <-time.After(poll):
		}
	}
}
