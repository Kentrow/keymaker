// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package ovh

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// rateLimitAttempts is how many times in all a call refused for its rate is sent.
	rateLimitAttempts = 4

	// rateLimitWait is the pause after a refusal that names no delay, and rateLimitCeiling
	// the longest one honoured: a reader is waiting on the other side of the page.
	rateLimitWait    = time.Second
	rateLimitCeiling = 10 * time.Second
)

// pacing sits under the SDK. When the API answers 429 Too Many Requests, it waits as long as
// that answer asks, within a ceiling, before handing it back, and the client then sends the
// call again, signed anew. The wait has to happen here: the SDK keeps no header of an answer,
// so Retry-After can only be read before the answer reaches it.
//
// An inventory makes one call per key and per application, several at a time, so an account
// holding hundreds of keys is the one most likely to meet the limit.
type pacing struct {
	next     http.RoundTripper
	fallback time.Duration
	ceiling  time.Duration
}

func (p pacing) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.next.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		return resp, err
	}

	timer := time.NewTimer(p.delay(resp.Header.Get("Retry-After"), time.Now()))
	defer timer.Stop()
	select {
	case <-req.Context().Done():
		_ = resp.Body.Close()
		return nil, req.Context().Err()
	case <-timer.C:
	}
	return resp, nil
}

// delay reads Retry-After in either of its forms, a number of seconds or a date, and keeps it
// between zero and the ceiling. Anything unreadable gets the fallback.
func (p pacing) delay(header string, now time.Time) time.Duration {
	wait := p.fallback
	header = strings.TrimSpace(header)
	if seconds, err := strconv.Atoi(header); err == nil && seconds >= 0 {
		// Compared in seconds first: a delay of billions of seconds would overflow a
		// Duration and come out negative, which would mean no wait at all.
		wait = p.ceiling
		if seconds < int(p.ceiling/time.Second) {
			wait = time.Duration(seconds) * time.Second
		}
	} else if at, err := http.ParseTime(header); err == nil {
		wait = at.Sub(now)
	}
	return min(max(wait, 0), p.ceiling)
}
