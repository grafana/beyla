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

package agent

import (
	"fmt"
	"regexp"
	"strings"
)

type interfaceFilter struct {
	allowedRegexpes  []*regexp.Regexp
	allowedMatches   []string
	excludedRegexpes []*regexp.Regexp
	excludedMatches  []string
}

// initInterfaceFilter allows filtering network interfaces that are accepted/excluded by the user,
// according to the provided allowed and excluded interfaces from the configuration. It allows
// matching by exact string or by regular expression
func initInterfaceFilter(allowed, excluded []string) (interfaceFilter, error) {
	isRegexp := regexp.MustCompile("^/(.*)/$")

	itf := interfaceFilter{}
	for _, definition := range allowed {
		definition = strings.Trim(definition, " ")
		// the user defined a /regexp/ between slashes: compile and store it as regular expression
		if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 1 {
			re, err := regexp.Compile(sm[1])
			if err != nil {
				return itf, fmt.Errorf("wrong interface regexp %q: %w", definition, err)
			}
			itf.allowedRegexpes = append(itf.allowedRegexpes, re)
		} else {
			// otherwise, store it as exact match definition
			itf.allowedMatches = append(itf.allowedMatches, definition)
		}
	}

	for _, definition := range excluded {
		definition = strings.Trim(definition, " ")
		// the user defined a /regexp/ between slashes: compile and store it as regexp
		if sm := isRegexp.FindStringSubmatch(definition); len(sm) > 1 {
			re, err := regexp.Compile(sm[1])
			if err != nil {
				return itf, fmt.Errorf("wrong excluded interface regexp %q: %w", definition, err)
			}
			itf.excludedRegexpes = append(itf.excludedRegexpes, re)
		} else {
			// otherwise, store it as exact match definition
			itf.excludedMatches = append(itf.excludedMatches, definition)
		}
	}

	return itf, nil
}

func (itf *interfaceFilter) Allowed(name string) bool {
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
