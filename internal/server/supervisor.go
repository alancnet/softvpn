package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/softvpn/softvpn/internal/config"
)

// Supervisor runs the server and replaces it with a new configuration on
// request (Apply), without restarting the process. Everything around the
// server - the web UI's listener, say - keeps running across a restart.
type Supervisor struct {
	// Args is the command line the configuration comes from: directives,
	// and "--config FILE".
	Args []string
	Log  *slog.Logger
	// OnStart, if set, is called with each configuration just before the
	// server starts with it (to adjust the log level to its verb, say).
	OnStart func(*Config)

	applyMu sync.Mutex // one Apply at a time

	mu      sync.RWMutex
	ctx     context.Context
	srv     *Server // nil while restarting
	gen     int     // bumped on every start, so a stale exit is ignored
	fail    chan error
	applied time.Time // last successful Apply
}

// ConfigFile is the configuration file named on the command line, or "".
func (sv *Supervisor) ConfigFile() string { return config.ConfigFile(sv.Args) }

// Load parses and validates the command line's configuration, as the
// server would at startup. If text is not nil, it stands in for the
// contents of the configuration file.
func (sv *Supervisor) Load(text *string) (*config.Config, *Config, error) {
	var override func(string) (string, bool)
	if text != nil {
		file := sv.ConfigFile()
		override = func(f string) (string, bool) { return *text, f == file }
	}
	c, err := config.ParseArgsWith(sv.Args, override)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := Load(c)
	if err != nil {
		return c, nil, err
	}
	// New reads and checks the client-config-dir files.
	if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		return c, nil, err
	}
	return c, cfg, nil
}

// Server is the running server, or nil while it is being restarted.
func (sv *Supervisor) Server() *Server {
	sv.mu.RLock()
	defer sv.mu.RUnlock()
	return sv.srv
}

// LastApplied is when a configuration was last applied (zero if never).
func (sv *Supervisor) LastApplied() time.Time {
	sv.mu.RLock()
	defer sv.mu.RUnlock()
	return sv.applied
}

// Run starts the server with cfg and runs until ctx is cancelled or the
// server fails.
func (sv *Supervisor) Run(ctx context.Context, cfg *Config) error {
	sv.mu.Lock()
	sv.ctx, sv.fail = ctx, make(chan error, 1)
	sv.mu.Unlock()
	if err := sv.start(cfg); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		sv.applyMu.Lock()
		defer sv.applyMu.Unlock()
		if srv := sv.take(); srv != nil {
			srv.Wait()
		}
		return nil
	case err := <-sv.fail:
		return err
	}
}

func (sv *Supervisor) start(cfg *Config) error {
	if sv.OnStart != nil {
		sv.OnStart(cfg)
	}
	srv, err := New(cfg, sv.Log)
	if err != nil {
		return err
	}
	sv.mu.RLock()
	ctx := sv.ctx
	sv.mu.RUnlock()
	if err := srv.Start(ctx); err != nil {
		return err
	}
	sv.mu.Lock()
	sv.srv = srv
	sv.gen++
	gen := sv.gen
	sv.mu.Unlock()
	go func() {
		err := srv.Wait()
		sv.mu.Lock()
		defer sv.mu.Unlock()
		if sv.gen == gen && sv.srv == srv && sv.ctx.Err() == nil {
			if err == nil {
				err = errors.New("server stopped unexpectedly")
			}
			select {
			case sv.fail <- err:
			default:
			}
		}
	}()
	return nil
}

// take removes the running server from the supervisor (so that its exit is
// not taken as a failure) and returns it.
func (sv *Supervisor) take() *Server {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	srv := sv.srv
	sv.srv = nil
	sv.gen++
	return srv
}

// ApplyError is returned by Apply when the new configuration did not start.
type ApplyError struct {
	Err        error // why the new configuration failed
	RolledBack bool  // the previous configuration is running again
}

func (e *ApplyError) Error() string {
	if e.RolledBack {
		return fmt.Sprintf("the new configuration did not start: %v (the previous configuration is running again)", e.Err)
	}
	return fmt.Sprintf("the new configuration did not start: %v", e.Err)
}

func (e *ApplyError) Unwrap() error { return e.Err }

// restartGrace is how long connected clients get to receive the RESTART
// message before the server stops.
var restartGrace = time.Second

// Apply restarts the server with cfg: connected clients are told to
// reconnect, the server stops and the new one starts. If the new one cannot
// start (its port is in use, say), the previous configuration is started
// again and an *ApplyError says what happened. If even that fails, the
// supervisor's Run returns the error.
func (sv *Supervisor) Apply(cfg *Config) error {
	sv.applyMu.Lock()
	defer sv.applyMu.Unlock()
	sv.mu.RLock()
	running := sv.ctx != nil && sv.ctx.Err() == nil
	sv.mu.RUnlock()
	if !running {
		return errors.New("the server is shutting down")
	}
	old := sv.take()
	if old != nil {
		if n := old.RestartClients(); n > 0 {
			sv.Log.Info("restarting with the new configuration; clients will reconnect", "clients", n)
			time.Sleep(restartGrace)
		}
		old.Stop()
	}
	if err := sv.start(cfg); err != nil {
		sv.Log.Error("new configuration failed to start", "err", err)
		if old == nil {
			return &ApplyError{Err: err}
		}
		if err2 := sv.start(old.Config()); err2 != nil {
			sv.Log.Error("previous configuration failed to start again", "err", err2)
			select {
			case sv.fail <- fmt.Errorf("restarting with the previous configuration: %w", err2):
			default:
			}
			return &ApplyError{Err: fmt.Errorf("%v; restarting the previous configuration also failed: %v", err, err2)}
		}
		sv.Log.Warn("previous configuration restored")
		return &ApplyError{Err: err, RolledBack: true}
	}
	sv.mu.Lock()
	sv.applied = time.Now()
	sv.mu.Unlock()
	sv.Log.Info("new configuration applied")
	return nil
}
