// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package ovh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/ovh/go-ovh/ovh"
)

// limited answers 429 to the first refusals calls of route, with retryAfter as the header,
// then serves the fixture. The clock is always answered.
func limited(t *testing.T, refusals int32, retryAfter, method, route, fixture string) (*APIClient, *atomic.Int32) {
	t.Helper()

	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/1.0/auth/time" {
			_, _ = w.Write([]byte(strconv.FormatInt(time.Now().Unix(), 10)))
			return
		}
		if r.Method != method || r.URL.Path != route {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if calls.Add(1) <= refusals {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message":"Too many requests"}`))
			return
		}
		if fixture == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		content, err := os.ReadFile(path.Join("testdata", fixture))
		if err != nil {
			t.Errorf("read fixture: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	transport := pacing{next: server.Client().Transport, fallback: 5 * time.Millisecond, ceiling: 20 * time.Millisecond}
	client := &sdk.Client{
		AppKey: "test-application-key", AppSecret: "test-application-secret", ConsumerKey: "test-consumer-key",
		Client: &http.Client{Transport: transport}, Timeout: requestTimeout, UserAgent: userAgent,
	}
	if err := client.SetEndpoint(server.URL + "/1.0"); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}
	return &APIClient{sdk: client, endpointURL: server.URL + "/1.0"}, calls
}

// An account with hundreds of keys is read one call per key: a refusal for the rate is waited
// out and the call sent again, rather than leaving that key out of the inventory.
func TestARateLimitedReadIsSentAgain(t *testing.T) {
	client, calls := limited(t, 2, "0", http.MethodGet, "/1.0/me/api/credential/4210987", "credential_validated.json")

	got, err := client.Credential(context.Background(), 4210987)
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if got.ID != 4210987 || calls.Load() != 3 {
		t.Errorf("ID = %d after %d calls, want 4210987 after 3", got.ID, calls.Load())
	}
}

// A call refused for its rate was not carried out, so a write is sent again as safely as a read.
func TestARateLimitedWriteIsSentAgain(t *testing.T) {
	client, calls := limited(t, 1, "", http.MethodDelete, "/1.0/me/api/credential/42", "")

	if err := client.DeleteCredential(context.Background(), 42); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
}

// A limit that does not lift is reported, after a bounded number of tries and a bounded wait.
func TestARateLimitThatHoldsIsReported(t *testing.T) {
	client, calls := limited(t, 100, "3600", http.MethodGet, "/1.0/me/api/credential/1", "credential_validated.json")

	started := time.Now()
	_, err := client.Credential(context.Background(), 1)
	if StatusCode(err) != http.StatusTooManyRequests {
		t.Fatalf("err = %v, want a 429", err)
	}
	if calls.Load() != rateLimitAttempts {
		t.Errorf("calls = %d, want %d", calls.Load(), rateLimitAttempts)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("took %s: an hour-long Retry-After was not held to the ceiling", elapsed)
	}
}

func TestRetryAfterIsReadInBothFormsAndBounded(t *testing.T) {
	p := pacing{fallback: time.Second, ceiling: 10 * time.Second}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	cases := map[string]time.Duration{
		"":                              time.Second,
		"3":                             3 * time.Second,
		" 0 ":                           0,
		"3600":                          10 * time.Second,
		"-5":                            time.Second,
		"soon":                          time.Second,
		"Sun, 04 Oct 2026 12:00:04 GMT": 4 * time.Second,
		"Sun, 04 Oct 2026 11:00:00 GMT": 0,
	}
	for header, want := range cases {
		if got := p.delay(header, now); got != want {
			t.Errorf("delay(%q) = %s, want %s", header, got, want)
		}
	}
}

// Waiting out a limit stops when the reader has gone.
func TestAWaitForTheRateEndsWithTheRequest(t *testing.T) {
	client, _ := limited(t, 100, "3600", http.MethodGet, "/1.0/me/api/credential/1", "credential_validated.json")
	client.sdk.Client.Transport = pacing{next: client.sdk.Client.Transport.(pacing).next, fallback: time.Hour, ceiling: time.Hour}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := client.Credential(ctx, 1); err == nil {
		t.Fatal("Credential succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Errorf("took %s after the request was cancelled", elapsed)
	}
}
