// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"
)

// The stylesheet is hand-written, has no build step and no linter in front of it, so the
// mistakes it is prone to are the ones a browser accepts in silence: two components given
// the same class name, a modifier that collides with a component, a custom property read
// but never declared. Each of these shipped at least once. The parser below understands
// the subset of CSS this file is written in - flat rules, no nesting, no :is() or :where()
// carrying a selector list - which is enough to hold that shape in place.

type declaration struct {
	property string
	value    string
}

type styleRule struct {
	line      int
	selectors []string
	decls     []declaration
	inAtRule  bool
}

func readStylesheet(t *testing.T) string {
	t.Helper()
	css, err := Assets().(interface {
		ReadFile(string) ([]byte, error)
	}).ReadFile("app.css")
	if err != nil {
		t.Fatalf("read app.css: %v", err)
	}
	return string(css)
}

func readAsset(t *testing.T, name string) string {
	t.Helper()
	body, err := Assets().(interface {
		ReadFile(string) ([]byte, error)
	}).ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

// stripComments blanks comments while keeping every byte offset and newline, so a rule
// still reports the line it is written on.
func stripComments(css string) string {
	out := []byte(css)
	for i := 0; i < len(out)-1; {
		if out[i] == '/' && out[i+1] == '*' {
			j := i + 2
			for j < len(out)-1 && (out[j] != '*' || out[j+1] != '/') {
				if out[j] != '\n' {
					out[j] = ' '
				}
				j++
			}
			out[i], out[i+1] = ' ', ' '
			if j < len(out)-1 {
				out[j], out[j+1] = ' ', ' '
			}
			i = j + 2
			continue
		}
		i++
	}
	return string(out)
}

func parseStylesheet(css string) []styleRule {
	css = stripComments(css)
	var rules []styleRule
	parseBlock(css, 0, len(css), false, &rules)
	return rules
}

// parseBlock reads the rules between two offsets. Conditional at-rules are walked into,
// because what they hold are rules; every other at-rule holds something else and is
// skipped whole.
func parseBlock(css string, from, to int, inAtRule bool, rules *[]styleRule) {
	i := from
	for i < to {
		start := strings.IndexAny(css[i:to], "{;")
		if start < 0 {
			return
		}
		start += i
		prelude := strings.TrimSpace(css[i:start])

		if css[start] == ';' {
			i = start + 1
			continue
		}

		end := matchingBrace(css, start)
		if end < 0 || end > to {
			return
		}

		if strings.HasPrefix(prelude, "@") {
			name := strings.ToLower(strings.Fields(prelude[1:])[0])
			if name == "media" || name == "supports" {
				parseBlock(css, start+1, end, true, rules)
			}
			i = end + 1
			continue
		}

		*rules = append(*rules, styleRule{
			line:      strings.Count(css[:start], "\n") + 1,
			selectors: splitSelectors(prelude),
			decls:     parseDeclarations(css[start+1 : end]),
			inAtRule:  inAtRule,
		})
		i = end + 1
	}
}

func matchingBrace(css string, open int) int {
	depth := 0
	for i := open; i < len(css); i++ {
		switch css[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func parseDeclarations(block string) []declaration {
	var decls []declaration
	for _, piece := range splitTopLevel(block, ';') {
		colon := strings.Index(piece, ":")
		if colon < 0 {
			continue
		}
		property := strings.TrimSpace(piece[:colon])
		if property == "" {
			continue
		}
		decls = append(decls, declaration{
			property: property,
			value:    strings.Join(strings.Fields(piece[colon+1:]), " "),
		})
	}
	return decls
}

func splitSelectors(prelude string) []string {
	var out []string
	for _, piece := range splitTopLevel(prelude, ',') {
		if trimmed := strings.TrimSpace(piece); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// splitTopLevel cuts on a separator that is not inside brackets, parentheses or a string.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, quote, start := 0, byte(0), 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[':
			depth++
		case c == ')' || c == ']':
			depth--
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// compounds cuts a selector at its combinators. What comes back is the list of pieces that
// each apply to one element, which is what decides whether two classes are on the same
// element or on two different ones.
func compounds(selector string) []string {
	var out []string
	depth, quote, start := 0, byte(0), 0
	flush := func(end int) {
		if piece := strings.TrimSpace(selector[start:end]); piece != "" {
			out = append(out, piece)
		}
	}
	for i := 0; i < len(selector); i++ {
		c := selector[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '(' || c == '[':
			depth++
		case c == ')' || c == ']':
			depth--
		case depth == 0 && (c == ' ' || c == '>' || c == '+' || c == '~'):
			flush(i)
			start = i + 1
		}
	}
	flush(len(selector))
	return out
}

var classPattern = regexp.MustCompile(`\.(-?[A-Za-z_][A-Za-z0-9_-]*)`)

// classesIn lists the classes of one compound, ignoring anything inside a functional
// pseudo-class, which applies to another element.
func classesIn(compound string) []string {
	depth, plain := 0, strings.Builder{}
	for i := 0; i < len(compound); i++ {
		switch compound[i] {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
			continue
		}
		if depth == 0 {
			plain.WriteByte(compound[i])
		}
	}
	var out []string
	for _, match := range classPattern.FindAllStringSubmatch(plain.String(), -1) {
		out = append(out, match[1])
	}
	return out
}

// bare reports the class a rule styles on its own, if that is what the rule does: one
// selector, one compound, one class and nothing else.
func (r styleRule) bare() (string, bool) {
	if len(r.selectors) != 1 || r.inAtRule {
		return "", false
	}
	parts := compounds(r.selectors[0])
	if len(parts) != 1 {
		return "", false
	}
	classes := classesIn(parts[0])
	if len(classes) != 1 || parts[0] != "."+classes[0] {
		return "", false
	}
	return classes[0], true
}

// family groups a shorthand with the longhands it overwrites, so that `margin: 0` is seen
// to land on an earlier `margin-top`.
func family(property string) string {
	for _, name := range []string{"margin", "padding", "border", "background", "font", "overflow", "gap", "inset"} {
		if property == name || strings.HasPrefix(property, name+"-") {
			return name
		}
	}
	return property
}

func touches(a, b string) bool {
	if a == b {
		return true
	}
	if family(a) != family(b) {
		return false
	}
	return a == family(a) || b == family(b)
}

// Two components under one class name is not a cascade anyone chose: whichever block comes
// last silently restyles the other, wherever the two touch the same property.
func TestStylesheetHasNoDuplicateComponent(t *testing.T) {
	seen := map[string][]styleRule{}
	for _, rule := range parseStylesheet(readStylesheet(t)) {
		if name, ok := rule.bare(); ok {
			seen[name] = append(seen[name], rule)
		}
	}

	for name, list := range seen {
		for i := 1; i < len(list); i++ {
			for j := 0; j < i; j++ {
				for _, later := range list[i].decls {
					for _, earlier := range list[j].decls {
						if !touches(later.property, earlier.property) || later.value == earlier.value {
							continue
						}
						t.Errorf(".%s: line %d silently overrides line %d (%s: %s becomes %s: %s)",
							name, list[i].line, list[j].line,
							earlier.property, earlier.value, later.property, later.value)
					}
				}
			}
		}
	}
}

// A class used as a modifier on a component must not also be a component of its own: the
// standalone rule wins on every property they share, whatever the author meant.
func TestStylesheetHasNoModifierCollision(t *testing.T) {
	rules := parseStylesheet(readStylesheet(t))

	standalone := map[string][]string{}
	for _, rule := range rules {
		if name, ok := rule.bare(); ok {
			for _, d := range rule.decls {
				if !strings.HasPrefix(d.property, "--") {
					standalone[name] = append(standalone[name], d.property)
				}
			}
		}
	}

	for _, rule := range rules {
		for _, selector := range rule.selectors {
			for _, compound := range compounds(selector) {
				classes := classesIn(compound)
				for _, modifier := range classes[min(1, len(classes)):] {
					if properties, clash := standalone[modifier]; clash {
						t.Errorf("%s: .%s is a modifier here and a component of its own, which sets %s",
							selector, modifier, strings.Join(properties, ", "))
					}
				}
			}
		}
	}
}

var readPattern = regexp.MustCompile(`var\(\s*(--[A-Za-z0-9_-]+)`)

// A property read but never declared renders as nothing, and one declared but never read
// is weight the next reader has to account for.
func TestStylesheetCustomPropertiesAreDeclaredAndRead(t *testing.T) {
	css := readStylesheet(t)

	declared := map[string]int{}
	for _, rule := range parseStylesheet(css) {
		for _, d := range rule.decls {
			if strings.HasPrefix(d.property, "--") {
				declared[d.property] = rule.line
			}
		}
	}

	read := map[string]bool{}
	for _, match := range readPattern.FindAllStringSubmatch(css, -1) {
		read[match[1]] = true
	}

	for name := range read {
		if _, ok := declared[name]; !ok {
			t.Errorf("%s is read but never declared", name)
		}
	}
	for name, line := range declared {
		if !read[name] {
			t.Errorf("%s is declared on line %d but never read", name, line)
		}
	}
}

var classAttribute = regexp.MustCompile(`(?:^|\s)class="([^"]*)"`)

// A class in the markup that no rule mentions is either a leftover or a rule that was
// renamed on one side only. Both have shipped.
func TestMarkupClassesAreStyled(t *testing.T) {
	styled := map[string]bool{}
	for _, rule := range parseStylesheet(readStylesheet(t)) {
		for _, selector := range rule.selectors {
			for _, compound := range compounds(selector) {
				for _, class := range classesIn(compound) {
					styled[class] = true
				}
			}
		}
	}

	markup := readAsset(t, "index.html")
	for _, match := range classAttribute.FindAllStringSubmatch(markup, -1) {
		for _, class := range strings.Fields(match[1]) {
			if !styled[class] {
				t.Errorf("class %q is in index.html but no rule styles it", class)
			}
		}
	}
}

var directive = regexp.MustCompile(`(?:^|\s)(x-[a-z]+(?::[a-z-]+)?(?:\.[a-z.]+)?)="([^"]*)"`)

var (
	propertyPath = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)
	iteration    = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]* in [A-Za-z_$][A-Za-z0-9_$.]*$`)
)

// The CSP build of Alpine evaluates no expression: a directive may name a property path or
// a method and nothing else. An expression slipped into one does not raise a build error
// because there is no build - it fails in the browser, on the one line that was never
// opened. Everything computed belongs in app.js, and this holds the markup to it.
func TestMarkupDirectivesNameAPathOrAMethod(t *testing.T) {
	for _, match := range directive.FindAllStringSubmatch(readAsset(t, "index.html"), -1) {
		name, value := match[1], match[2]
		if strings.HasPrefix(name, "x-for") {
			if !iteration.MatchString(value) {
				t.Errorf(`%s="%s" is not "item in items"`, name, value)
			}
			continue
		}
		if !propertyPath.MatchString(value) {
			t.Errorf(`%s="%s" is an expression, which the CSP build of Alpine cannot evaluate`, name, value)
		}
	}
}

var (
	subresource = regexp.MustCompile(`(?:\ssrc="([^"]*)")|(?:<link[^>]*\shref="([^"]*)")`)
	cssURL      = regexp.MustCompile(`url\(\s*["']?([^)"']*)`)
	scheme      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*:`)
)

// Nothing the browser loads may come from outside the binary: no CDN, no font, no script,
// no image. It is the third of the rules this project is held to and the one a single
// pasted line undoes, so it is checked rather than trusted. A data URI is the interface
// carrying its own asset and stays allowed.
func TestAssetsFetchNothingFromOutside(t *testing.T) {
	external := func(reference string) bool {
		return scheme.MatchString(reference) && !strings.HasPrefix(reference, "data:")
	}

	for _, match := range subresource.FindAllStringSubmatch(readAsset(t, "index.html"), -1) {
		for _, reference := range match[1:] {
			if reference != "" && external(reference) {
				t.Errorf("index.html loads %s from outside the binary", reference)
			}
		}
	}

	for _, match := range cssURL.FindAllStringSubmatch(readStylesheet(t), -1) {
		if external(match[1]) {
			t.Errorf("app.css loads %s from outside the binary", match[1])
		}
	}
}

var (
	labelReference  = regexp.MustCompile(`labels\.([A-Za-z][A-Za-z0-9]*)`)
	dictionaryStart = regexp.MustCompile(`(?m)^  (en|fr): \{$`)
	labelDefinition = regexp.MustCompile(`(?m)^    ([A-Za-z][A-Za-z0-9]*):`)
)

// dictionaries returns the labels each language defines. The block is bounded by brace
// balance rather than by the end of the file, which would take in the whole component that
// follows it.
func dictionaries(t *testing.T, script string) map[string]map[string]bool {
	t.Helper()

	opening := strings.Index(script, "const dictionaries = {")
	if opening < 0 {
		t.Fatal("no dictionaries in app.js")
	}
	block := script[opening : opening+balanced(script[opening:])]

	found := map[string]map[string]bool{}
	starts := dictionaryStart.FindAllStringSubmatchIndex(block, -1)
	if len(starts) != 2 {
		t.Fatalf("found %d dictionaries, want 2", len(starts))
	}

	for i, start := range starts {
		language := block[start[2]:start[3]]
		end := len(block)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		labels := map[string]bool{}
		for _, match := range labelDefinition.FindAllStringSubmatch(block[start[1]:end], -1) {
			labels[match[1]] = true
		}
		found[language] = labels
	}
	return found
}

// balanced reports the length of the brace-delimited block starting in s.
func balanced(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

// A label the markup asks for and no dictionary defines renders as nothing, and a label no
// markup asks for is weight that outlived whatever screen used to show it. Neither raises
// an error in a browser, and both have shipped.
func TestEveryLabelIsDefinedAndUsed(t *testing.T) {
	script := readAsset(t, "app.js")
	defined := dictionaries(t, script)

	asked := map[string]bool{}
	for _, source := range []string{readAsset(t, "index.html"), script} {
		for _, match := range labelReference.FindAllStringSubmatch(source, -1) {
			asked[match[1]] = true
		}
	}

	for name := range asked {
		for language, labels := range defined {
			if !labels[name] {
				t.Errorf("labels.%s is asked for but the %s dictionary does not define it", name, language)
			}
		}
	}

	for language, labels := range defined {
		for name := range labels {
			if !asked[name] {
				t.Errorf("labels.%s is defined in %s and asked for nowhere", name, language)
			}
		}
	}
}
