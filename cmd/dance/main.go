package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rcarmo/dance/internal/app"
)

func run(ctx context.Context) error {
	a, err := app.New(ctx)
	if err != nil {
		return err
	}
	stopped := make(chan error, 1)
	go func() { stopped <- a.Server.ListenAndServe() }()
	log.Printf("dance listening on %s", a.Config.Addr)
	select {
	case err = <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case <-ctx.Done():
	}
	// Shutdown drains requests before the authority and application DB close.
	return errors.Join(err, a.Close())
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Printf("dance failed: %v", err)
		os.Exit(1)
	}
}
