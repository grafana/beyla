// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package tcmanager

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// InterfaceFilter allows filtering network interfaces that are accepted/excluded by the user,
// according to the provided allowed and excluded interfaces from the configuration. It allows
// matching by exact string or by regular expression

type InterfaceFilter struct {
	allowedRegexpes  []*regexp.Regexp
	allowedMatches   []string
	excludedRegexpes []*regexp.Regexp
	excludedMatches  []string
	isRegexp         *regexp.Regexp
}

func NewInterfaceFilter(allowed []string, excluded []string) (*InterfaceFilter, error) {
	itf := InterfaceFilter{
		isRegexp: regexp.MustCompile("^/(.*)/$"),
	}

	for _, pattern := range allowed {
		if err := itf.Allow(pattern); err != nil {
			return nil, err
		}
	}

	for _, pattern := range excluded {
		if err := itf.Deny(pattern); err != nil {
			return nil, err
		}
	}

	ret := &itf
	return ret, nil
}

func (itf *InterfaceFilter) Allow(pattern string) error {
	return itf.addPattern(pattern, &itf.allowedRegexpes, &itf.allowedMatches)
}

func (itf *InterfaceFilter) Deny(pattern string) error {
	return itf.addPattern(pattern, &itf.excludedRegexpes, &itf.excludedMatches)
}

func (itf *InterfaceFilter) addPattern(pattern string,
	regexps *[]*regexp.Regexp, matches *[]string,
) error {
	if regexps == nil || matches == nil {
		return errors.New("logic error: addPattern has null params")
	}

	pattern = strings.Trim(pattern, " ")

	// the user defined a /regexp/ between slashes: compile and store it as regular expression
	if sm := itf.isRegexp.FindStringSubmatch(pattern); len(sm) > 1 {
		re, err := regexp.Compile(sm[1])
		if err != nil {
			return fmt.Errorf("wrong interface regexp %q: %w", pattern, err)
		}

		*regexps = append(*regexps, re)
	} else {
		// otherwise, store it as exact match pattern
		*matches = append(*matches, pattern)
	}

	return nil
}

func (itf *InterfaceFilter) IsAllowed(name string) bool {
	// if the allowed list is empty, any interface is allowed except if it matches the exclusion list
	allowed := len(itf.allowedRegexpes)+len(itf.allowedMatches) == 0

	// otherwise, we check if it appears in the allowed lists (both exact match and regexp)
	for i := 0; !allowed && i < len(itf.allowedMatches); i++ {
		allowed = allowed || name == itf.allowedMatches[i]
	}

	for i := 0; !allowed && i < len(itf.allowedRegexpes); i++ {
		allowed = allowed || itf.allowedRegexpes[i].MatchString(name)
	}

	if !allowed {
		return false
	}

	// if the interface matches the allow lists, we still need to check that is not excluded
	for _, match := range itf.excludedMatches {
		if name == match {
			return false
		}
	}

	for _, re := range itf.excludedRegexpes {
		if re.MatchString(name) {
			return false
		}
	}

	return true
}
