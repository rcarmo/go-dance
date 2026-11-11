package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/rcarmo/dance/internal/app"
)

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return serve(ctx)
	}
	switch args[0] {
	case "admin":
		return runAdmin(ctx, args[1:])
	case "serve":
		if len(args) != 1 {
			return fmt.Errorf("usage: dance serve")
		}
		return serve(ctx)
	case "-h", "--help", "help":
		fmt.Fprintln(os.Stdout, "Usage: dance [serve] | dance admin grant|revoke [options]\nNo command starts the server using DANCE_* environment configuration.\nAdmin commands manage optional scoped API credentials using the local app database.")
		return nil
	default:
		return fmt.Errorf("unknown command; use dance --help")
	}
}

func serve(ctx context.Context) error {
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
	if err := run(ctx, os.Args[1:]); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Printf("dance failed: %v", err)
		os.Exit(1)
	}
}
