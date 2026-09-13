// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// app.js has no compiler and no linter in front of it either. The mistakes below are the
// ones a removed feature leaves behind: a method still calling one that went with it, a
// getter nothing reads, an error code the backend stopped sending and both dictionaries
// still word. None of them raises anything in a browser until the one line that reaches
// them runs.

var (
	componentStart = regexp.MustCompile(`Alpine\.data\('inventory', \(\) => \(\{`)
	memberHead     = regexp.MustCompile(`(?m)^    (?:async |get )?([A-Za-z_][A-Za-z0-9_]*) \(`)
	methodCall     = regexp.MustCompile(`this\.([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
	memberRead     = regexp.MustCompile(`this\.([A-Za-z_][A-Za-z0-9_]*)`)
	directiveValue = regexp.MustCompile(`\sx-[a-z]+(?::[a-z-]+)?(?:\.[a-z.]+)?="([^"]*)"`)
	topLevel       = regexp.MustCompile(`(?m)^(?:const|function) ([A-Za-z_][A-Za-z0-9_]*)`)
	problemsStart  = regexp.MustCompile(`(?m)^    problems: \{$`)
	problemKey     = regexp.MustCompile(`(?m)^      '([a-z-]+)':`)
	codeConstant   = regexp.MustCompile(`code[A-Z][A-Za-z]*\s*=\s*"([a-z-]+)"`)
)

// component returns the body of the Alpine component, where its methods and getters live.
func component(t *testing.T, script string) string {
	t.Helper()
	start := componentStart.FindStringIndex(script)
	if start == nil {
		t.Fatal("no Alpine component in app.js")
	}
	return script[start[1]:]
}

func members(t *testing.T, script string) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	for _, match := range memberHead.FindAllStringSubmatch(component(t, script), -1) {
		found[match[1]] = true
	}
	return found
}

// A call to a method the component does not define throws the moment it runs, which for a
// getter bound to a hidden element can be long after the change that removed the method.
func TestScriptCallsOnlyMethodsItDefines(t *testing.T) {
	script := readAsset(t, "app.js")
	defined := members(t, script)

	for _, match := range methodCall.FindAllStringSubmatch(component(t, script), -1) {
		if !defined[match[1]] {
			t.Errorf("this.%s() is called but the component defines no such method", match[1])
		}
	}
}

// A method or getter that neither the markup nor another member reads is what a removed
// screen leaves behind. Alpine calls init itself.
func TestEveryComponentMemberIsUsed(t *testing.T) {
	script := readAsset(t, "app.js")
	body := component(t, script)

	used := map[string]bool{"init": true}
	for _, match := range memberRead.FindAllStringSubmatch(body, -1) {
		used[match[1]] = true
	}
	for _, match := range directiveValue.FindAllStringSubmatch(readAsset(t, "index.html"), -1) {
		for _, word := range regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`).FindAllString(match[1], -1) {
			used[word] = true
		}
	}

	for name := range members(t, script) {
		if !used[name] {
			t.Errorf("%s is defined on the component and read nowhere", name)
		}
	}
}

// The same for what sits outside the component: a constant or a helper function that only
// its own declaration mentions.
func TestEveryTopLevelDeclarationIsUsed(t *testing.T) {
	script := readAsset(t, "app.js")

	for _, match := range topLevel.FindAllStringSubmatch(script, -1) {
		name := match[1]
		if uses := regexp.MustCompile(`\b`+name+`\b`).FindAllStringIndex(script, -1); len(uses) < 2 {
			t.Errorf("%s is declared at the top of app.js and used nowhere", name)
		}
	}
}

// problemCodes returns the error codes each dictionary words.
func problemCodes(t *testing.T, script string) []map[string]bool {
	t.Helper()
	var found []map[string]bool
	for _, start := range problemsStart.FindAllStringIndex(script, -1) {
		block := script[start[0] : start[0]+balanced(script[start[0]:])]
		codes := map[string]bool{}
		for _, match := range problemKey.FindAllStringSubmatch(block, -1) {
			codes[match[1]] = true
		}
		found = append(found, codes)
	}
	if len(found) != 2 {
		t.Fatalf("found %d problems dictionaries, want 2", len(found))
	}
	return found
}

// backendCodes returns the error codes the HTTP layer declares.
func backendCodes(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "httpapi", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no source in internal/httpapi: %v", err)
	}

	codes := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		// #nosec G304 -- the paths come from a glob over this repository.
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		for _, match := range codeConstant.FindAllStringSubmatch(string(source), -1) {
			codes[match[1]] = true
		}
	}
	return codes
}

// An error code is a contract between the handlers and the dictionaries. A code the backend
// sends and no dictionary words falls back to an English sentence in a French interface; a
// code worded and never sent is a message for a failure that can no longer happen.
func TestProblemCodesMatchWhatTheBackendSends(t *testing.T) {
	sent := backendCodes(t)

	for i, worded := range problemCodes(t, readAsset(t, "app.js")) {
		for code := range worded {
			if !sent[code] {
				t.Errorf("dictionary %d words %q, which the backend never sends", i, code)
			}
		}
		for code := range sent {
			if !worded[code] {
				t.Errorf("the backend sends %q and dictionary %d does not word it", code, i)
			}
		}
	}
}

// templatedPrefix matches a class the script builds from a value, such as `method-${name}`,
// whose full name therefore never appears as written.
var templatedPrefix = regexp.MustCompile(`([a-z][a-z-]*-)\$\{`)

// A rule for a class that neither the markup nor the script ever sets styles nothing. It is
// what a removed screen leaves in the stylesheet, and it keeps every later reader wondering
// what it is for.
func TestEveryStyledClassIsUsed(t *testing.T) {
	markup, script := readAsset(t, "index.html"), readAsset(t, "app.js")
	source := markup + "\n" + script

	var prefixes []string
	for _, match := range templatedPrefix.FindAllStringSubmatch(script, -1) {
		prefixes = append(prefixes, match[1])
	}

	reported := map[string]bool{}
	for _, rule := range parseStylesheet(readStylesheet(t)) {
		for _, selector := range rule.selectors {
			for _, compound := range compounds(selector) {
				for _, class := range classesIn(compound) {
					if reported[class] || usedClass(source, class, prefixes) {
						continue
					}
					reported[class] = true
					t.Errorf("app.css line %d styles .%s, which neither index.html nor app.js sets", rule.line, class)
				}
			}
		}
	}
}

func usedClass(source, class string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(class, prefix) {
			return true
		}
	}
	word := regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(class) + `(?:$|[^A-Za-z0-9_-])`)
	return word.MatchString(source)
}
