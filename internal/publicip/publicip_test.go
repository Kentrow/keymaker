// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package publicip

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func resolverAnswering(t *testing.T, status int, body string) *Service {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)

	return &Service{client: server.Client(), endpoint: server.URL}
}

func TestAnAddressIsRead(t *testing.T) {
	for _, body := range []string{"203.0.113.7", "203.0.113.7\n", " 203.0.113.7 ", "2001:db8::1"} {
		got, err := resolverAnswering(t, http.StatusOK, body).Address(t.Context())
		if err != nil {
			t.Fatalf("Address(%q): %v", body, err)
		}
		if want := strings.TrimSpace(body); got.String() != want {
			t.Errorf("Address(%q) = %s, want %s", body, got, want)
		}
	}
}

func TestAnAnswerThatIsNotAnAddressIsRefused(t *testing.T) {
	// The value prefills a restriction deciding which machines a key answers to. An error
	// page turned into a rule would be a restriction nobody chose.
	for _, body := range []string{"", "<html>rate limited</html>", "not an address", "203.0.113.7/24"} {
		if _, err := resolverAnswering(t, http.StatusOK, body).Address(t.Context()); err == nil {
			t.Errorf("Address(%q) returned no error", body)
		}
	}
}

func TestAFailingResolverIsReported(t *testing.T) {
	if _, err := resolverAnswering(t, http.StatusTooManyRequests, "203.0.113.7").Address(t.Context()); err == nil {
		t.Fatal("expected an error, got none")
	}
}

func TestAnOversizedAnswerIsRefused(t *testing.T) {
	if _, err := resolverAnswering(t, http.StatusOK, strings.Repeat("9", 4096)).Address(t.Context()); err == nil {
		t.Fatal("expected an error, got none")
	}
}

func TestADisabledInstanceMakesNoCall(t *testing.T) {
	_, err := Disabled{}.Address(t.Context())
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("error = %v, want ErrDisabled", err)
	}
}

func TestTheResolverIsFixedInTheCode(t *testing.T) {
	// The destination is not configurable on purpose: the outbound guarantee is only
	// worth stating if a reader can see where the one exception points.
	if !strings.HasPrefix(service, "https://") {
		t.Errorf("service = %q, want https so that an on-path answer cannot prefill the field", service)
	}
	if New(http.DefaultClient).endpoint != service {
		t.Error("the constructor does not use the address declared in the package")
	}
}
