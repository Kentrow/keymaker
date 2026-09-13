// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const secret = "cccccccccccccccccccccccccccccccc"

func newTestLogger(t *testing.T, secrets ...string) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	redactor := &Redactor{}
	redactor.Add(secrets...)
	return slog.New(NewHandler(slog.NewJSONHandler(&buf, nil), redactor)), &buf
}

func TestScrubbedEverywhereARecordCarriesText(t *testing.T) {
	cases := map[string]func(l *slog.Logger){
		"message": func(l *slog.Logger) {
			l.Info("using consumer key " + secret)
		},
		"attribute value": func(l *slog.Logger) {
			l.Info("call", "consumer_key", secret)
		},
		"attribute key": func(l *slog.Logger) {
			l.Info("call", secret, "value")
		},
		"wrapped error": func(l *slog.Logger) {
			l.Error("call failed", "error", fmt.Errorf("auth: %w", errors.New(secret)))
		},
		"group member": func(l *slog.Logger) {
			l.Info("call", slog.Group("credential", slog.String("key", secret)))
		},
		"handler attribute": func(l *slog.Logger) {
			l.With("consumer_key", secret).Info("call")
		},
		"handler group": func(l *slog.Logger) {
			l.WithGroup("account").Info("call", "consumer_key", secret)
		},
	}

	for name, log := range cases {
		t.Run(name, func(t *testing.T) {
			logger, buf := newTestLogger(t, secret)
			log(logger)

			if strings.Contains(buf.String(), secret) {
				t.Fatalf("secret reached the log: %s", buf.String())
			}
			if !strings.Contains(buf.String(), Placeholder) {
				t.Errorf("no placeholder in output: %s", buf.String())
			}
		})
	}
}

func TestUntaintedValuesKeepTheirType(t *testing.T) {
	logger, buf := newTestLogger(t, secret)
	logger.Info("listing", "count", 12)

	if !strings.Contains(buf.String(), `"count":12`) {
		t.Errorf("number was rewritten as text: %s", buf.String())
	}
}

func TestEmptySecretIsIgnored(t *testing.T) {
	logger, buf := newTestLogger(t, "")
	logger.Info("listing", "endpoint", "ovh-eu")

	if strings.Contains(buf.String(), Placeholder) {
		t.Errorf("empty value matched: %s", buf.String())
	}
}
