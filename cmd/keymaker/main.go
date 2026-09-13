// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Command keymaker serves the local web interface that inventories, revokes and
// creates OVHcloud API keys.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kentrow/keymaker/internal/catalog"
	"github.com/kentrow/keymaker/internal/config"
	"github.com/kentrow/keymaker/internal/httpapi"
	"github.com/kentrow/keymaker/internal/legacy"
	"github.com/kentrow/keymaker/internal/logging"
	"github.com/kentrow/keymaker/internal/ovh"
	"github.com/kentrow/keymaker/internal/publicip"
	"github.com/kentrow/keymaker/internal/web"
)

// Build information, set at link time by a release build:
//
//	-ldflags="-X main.version=0.1.0 -X main.commit=<sha> -X main.date=<RFC 3339>"
//
// A build made without them says so rather than claiming a version it is not.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// defaultAddr keeps the process on the loopback interface unless it is told otherwise. The
// published image overrides it, because a process bound to loopback inside a network
// namespace is unreachable through a published port; there the boundary is the host-side
// port mapping.
const defaultAddr = "127.0.0.1:8080"

// defaultConfigPath is where the documented run command mounts the file, read-only.
const defaultConfigPath = "/config/ovh.conf"

const shutdownGrace = 10 * time.Second

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		slog.Error("keymaker stopped", "error", err)
		os.Exit(1)
	}
}

// versionLine is what --version prints and what the startup log records.
func versionLine() string {
	return fmt.Sprintf("keymaker %s (commit %s, built %s)", version, commit, date)
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("keymaker", flag.ContinueOnError)
	showVersion := flags.Bool("version", false, "print the version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, versionLine())
		return err
	}

	addr := environment("KEYMAKER_ADDR", defaultAddr)

	account, redactor, err := load(environment("KEYMAKER_CONFIG", defaultConfigPath))
	if err != nil {
		return err
	}

	level, err := logLevel(os.Getenv("KEYMAKER_LOG_LEVEL"))
	if err != nil {
		return err
	}

	logger := slog.New(logging.NewHandler(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}), redactor))
	slog.SetDefault(logger)
	logger.Info("starting", "version", version, "commit", commit, "date", date)

	client, err := ovh.NewAPIClient(account, &http.Client{})
	if err != nil {
		return err
	}

	token, err := httpapi.NewToken()
	if err != nil {
		return err
	}

	csrf, err := httpapi.NewToken()
	if err != nil {
		return err
	}

	routes := routeCatalogue(client, logger)

	public, err := baseURL(addr, os.Getenv("KEYMAKER_PUBLIC_URL"))
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr: addr,
		Handler: httpapi.New(httpapi.Options{
			Provider: legacy.New(client, logger),
			Catalog:  routes,
			Assets:   web.Assets(),
			Logger:   logger,
			Token:    token,
			CSRF:     csrf,
			Endpoint: account.Endpoint,
			Version:  version,
			Resolver: addressResolver(logger),
		}),
		// The server reports its own failures, a broken connection or a malformed request,
		// through the same pipeline as everything else, so redaction applies to them too.
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// The published image binds beyond loopback by necessity, so this warning fires on
	// every containerised start. It names the mitigation rather than only the risk, so
	// that the expected case reads as expected and the signal keeps its value.
	if !bindsLoopback(addr) {
		logger.Warn("listening beyond loopback, whatever reaches this address reaches the interface; in a container the host port mapping is what restricts it", "addr", addr)
	}

	// The access token is deliberately not registered with the redactor: this line is the
	// only way the user gets it, and it is printed once, at startup, to the terminal that
	// started the process. No request path logs a query string, so it does not reappear.
	logger.Info("open this address to use the interface", "url", entryPoint(public, token))

	// Fetching seventy schema documents takes a couple of seconds, which the inventory
	// has no reason to wait for. The explorer is the only screen that needs them, and it
	// waits on this refresh rather than showing the embedded snapshot it would then have
	// to replace under the reader.
	catalogueContext, stopRefresh := context.WithCancel(context.Background())
	defer stopRefresh()
	routes.RefreshInBackground(catalogueContext)

	return serve(srv, logger)
}

func routeCatalogue(client *ovh.APIClient, logger *slog.Logger) *catalog.Remote {
	embedded, err := catalog.Embedded()
	if err != nil {
		// A corrupt embedded snapshot is a build defect, not an operating condition. The
		// explorer is unusable until the refresh lands, and everything else still works,
		// so this is reported rather than fatal.
		logger.Error("the embedded route catalogue could not be read", "error", err)
	}
	return catalog.NewRemote(client, embedded, logger)
}

// load reads the configuration and registers its secrets with the redactor before
// anything else can log. The redactor is built here, and not later, so that no code path
// exists in which a credential is in memory while the logger still writes it out.
func load(path string) (config.Account, *logging.Redactor, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return config.Account{}, nil, err
	}

	account, err := cfg.Account()
	if err != nil {
		return config.Account{}, nil, err
	}

	redactor := &logging.Redactor{}
	redactor.Add(account.Management.ApplicationSecret, account.Management.ConsumerKey)
	return account, redactor, nil
}

func serve(srv *http.Server, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	listening := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", srv.Addr)
		listening <- srv.ListenAndServe()
	}()

	select {
	case err := <-listening:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}

	shutdown, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	return srv.Shutdown(shutdown)
}

// logLevel reads KEYMAKER_LOG_LEVEL. Debug adds one line per request; the default is info.
// An unknown value stops the process rather than being ignored, so a typo does not silently
// leave the reader without the lines they asked for.
func logLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("KEYMAKER_LOG_LEVEL %q is not one of debug, info, warn or error", value)
	}
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// entryPoint is the address to open in a browser.
func entryPoint(public *url.URL, token string) string {
	entry := *public
	entry.Path = "/"
	entry.RawQuery = url.Values{"token": {token}}.Encode()
	return entry.String()
}

// addressResolver decides whether this instance may look its public address up. The
// lookup is the one outbound call outside the OVHcloud API and it is opt-in per use, but
// an operator who wants the guarantee absolute can take the ability away entirely.
func addressResolver(logger *slog.Logger) publicip.Resolver {
	if strings.EqualFold(os.Getenv("KEYMAKER_IP_LOOKUP"), "off") {
		logger.Info("public address lookup disabled, this instance contacts nothing but the OVHcloud API")
		return publicip.Disabled{}
	}
	return publicip.New(&http.Client{})
}

func baseURL(addr, public string) (*url.URL, error) {
	if public == "" {
		return listenURL(addr), nil
	}

	parsed, err := url.Parse(public)
	if err != nil {
		return nil, fmt.Errorf("KEYMAKER_PUBLIC_URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("KEYMAKER_PUBLIC_URL must be absolute, such as http://127.0.0.1:8080")
	}
	return parsed, nil
}

// listenURL turns the bind address into something clickable. A process listening on every
// interface is still reached through loopback from the machine that started it, so the
// printed address says 127.0.0.1 rather than repeating a bind address nobody can open.
func listenURL(addr string) *url.URL {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return &url.URL{Scheme: "http", Host: addr}
	}

	if ip, parseErr := netip.ParseAddr(host); host == "" || (parseErr == nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
}

// bindsLoopback reports whether addr reaches the loopback interface only. An address
// it cannot resolve to a literal IP counts as exposed, so an unusual spelling produces
// a warning rather than silence.
func bindsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}
