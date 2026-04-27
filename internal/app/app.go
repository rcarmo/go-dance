package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/rcarmo/dance/internal/config"
	"github.com/rcarmo/dance/internal/httpserver"
	"github.com/rcarmo/dance/internal/stepca"
	"github.com/rcarmo/dance/internal/store"
)

type App struct {
	Config *config.Config
	Store  store.Store
	StepCA *stepca.Manager
	Server *http.Server
}

func New(ctx context.Context) (*App, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	st, err := store.NewSQLite(cfg.DBPath)
	if err != nil {
		return nil, err
	}
	if err := st.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	if err := st.EnsureAdmin(ctx, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		return nil, err
	}
	mgr, err := stepca.New(ctx, cfg.BaseURL, cfg.StepCAURL, cfg.StepCAConfig, cfg.StepCAPassword)
	if err != nil {
		return nil, err
	}

	handler, err := httpserver.New(cfg, st, mgr)
	if err != nil {
		return nil, fmt.Errorf("build handler: %w", err)
	}

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	return &App{Config: cfg, Store: st, StepCA: mgr, Server: server}, nil
}

func (a *App) Close() error {
	if a.StepCA != nil {
		_ = a.StepCA.Close()
	}
	if a.Store != nil {
		return a.Store.Close()
	}
	return nil
}
