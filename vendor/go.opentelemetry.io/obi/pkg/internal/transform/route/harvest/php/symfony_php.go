// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "strings"

// extractSymfonyPHPConfig harvests routes declared through Symfony’s PHP RoutingConfigurator
func extractSymfonyPHPConfig(tokens []token, routes routeSet) {
	routingConfigurators := symfonyRoutingConfiguratorVariables(tokens)
	for pos := 0; pos+3 < len(tokens); pos++ {
		if tokens[pos].kind != tokenVariable {
			continue
		}

		if _, isRoutingConfigurator := routingConfigurators[tokens[pos].value]; !isRoutingConfigurator {
			continue
		}

		if tokens[pos+1].value != "->" {
			continue
		}

		if !equalName(tokens[pos+2], "add") || tokens[pos+3].value != "(" {
			continue
		}

		arguments := callArguments(tokens, pos+3)
		path, ok := staticStringArgument(arguments, 1)
		if !ok {
			path, ok = namedLiteralArgument(arguments, "path")
		}
		if ok {
			routes.add(path)
		}
	}
}

// symfonyRoutingConfiguratorVariables finds variables and arguments whose type is RoutingConfigurator
func symfonyRoutingConfiguratorVariables(tokens []token) map[string]struct{} {
	variables := map[string]struct{}{}
	for pos := range len(tokens) {
		if tokens[pos].kind != tokenName || !strings.EqualFold(shortPHPName(tokens[pos].value), "RoutingConfigurator") {
			continue
		}

		if pos+1 < len(tokens) && tokens[pos+1].kind == tokenVariable {
			variables[tokens[pos+1].value] = struct{}{}
		}
	}

	return variables
}
