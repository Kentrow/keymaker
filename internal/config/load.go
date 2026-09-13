// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
)

// applicationsSection is not read: it held the application keys the old creation path
// issued under, and an ovh.conf written for a previous version may still carry it. Naming
// it here is what keeps it from being mistaken for an endpoint section.
const applicationsSection = "applications"

const defaultSection = "default"

// Load reads the configuration file. The file is only ever read: nothing in this package
// writes it back, and no value it carries reaches an error message, since a malformed
// line could otherwise put a secret in a log.
func Load(path string) (Config, error) {
	// #nosec G304 -- the path names the file the operator chose to mount; there is no
	// other file to read, and it never comes from a request.
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", annotate(err))
	}
	defer func() { _ = f.Close() }()

	cfg, err := parse(f)
	if err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// annotate adds the identity the process is running under when the file was there but
// could not be read. A configuration file holding secrets is expected to be readable by
// its owner alone, and in a container the process is rarely that owner; without the
// identity the reader is left comparing a file mode against a user they cannot see.
func annotate(err error) error {
	if !errors.Is(err, fs.ErrPermission) {
		return err
	}
	return fmt.Errorf("%w (this process runs as uid %d, gid %d)", err, os.Getuid(), os.Getgid())
}

// parse reads the subset of the INI format the official SDK configuration files use:
// bracketed sections, key=value pairs, and comments introduced by ';' or '#'. Values
// are taken literally, so a secret containing '#' survives intact.
func parse(r io.Reader) (Config, error) {
	sections := map[string]map[string]string{}
	order := []string{}

	current := ""
	scanner := bufio.NewScanner(r)
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, ";") || strings.HasPrefix(text, "#") {
			continue
		}

		if strings.HasPrefix(text, "[") {
			if !strings.HasSuffix(text, "]") {
				return Config{}, fmt.Errorf("line %d: unterminated section header", line)
			}
			current = strings.TrimSpace(text[1 : len(text)-1])
			if current == "" {
				return Config{}, fmt.Errorf("line %d: empty section name", line)
			}
			if _, seen := sections[current]; !seen {
				sections[current] = map[string]string{}
				order = append(order, current)
			}
			continue
		}

		key, value, found := strings.Cut(text, "=")
		if !found {
			return Config{}, fmt.Errorf("line %d: expected key=value", line)
		}
		if current == "" {
			return Config{}, fmt.Errorf("line %d: key outside of any section", line)
		}
		sections[current][strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return Config{}, err
	}

	return build(sections, order)
}

func build(sections map[string]map[string]string, order []string) (Config, error) {
	cfg := Config{Default: sections[defaultSection]["endpoint"]}
	for _, name := range order {
		if name == defaultSection || name == applicationsSection {
			continue
		}
		values := sections[name]
		cfg.Accounts = append(cfg.Accounts, Account{
			Name:     name,
			Endpoint: name,
			Management: LegacyCredentials{
				ApplicationKey:    values["application_key"],
				ApplicationSecret: values["application_secret"],
				ConsumerKey:       values["consumer_key"],
			},
		})
	}

	if len(cfg.Accounts) == 0 {
		return Config{}, errors.New("no endpoint section found")
	}
	if cfg.Default == "" {
		cfg.Default = cfg.Accounts[0].Name
	}
	if _, ok := sections[cfg.Default]; !ok {
		return Config{}, fmt.Errorf("default endpoint %q has no matching section", cfg.Default)
	}
	return cfg, nil
}

// Account returns the account the tool drives. It exposes a single one, but the lookup
// goes through the list so that adding a selector later changes nothing here.
func (c Config) Account() (Account, error) {
	for _, a := range c.Accounts {
		if a.Name == c.Default {
			return a, nil
		}
	}
	return Account{}, fmt.Errorf("no account named %q", c.Default)
}

// Complete reports whether the management credential has every part needed to sign a
// request. An incomplete one is a configuration mistake, not a degraded mode.
func (l LegacyCredentials) Complete() bool {
	return l.ApplicationKey != "" && l.ApplicationSecret != "" && l.ConsumerKey != ""
}
