// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/obi/pkg/internal/transform/route/harvest/php"

import "context"

func ExtractRoutes(ctx context.Context, root string) ([]string, error) {
	found, ok := readFrameworks(root)
	if !ok || !found.supported() {
		return nil, nil
	}

	routes := newRouteSet()
	symfonyAttributes := map[string][]string{}
	apiPrefix := laravelAPIPrefix{}
	if found.laravel {
		apiPrefix = readLaravelAPIPrefix(root)
	}

	err := walkPHPFiles(ctx, root, func(file phpFile) {
		if found.laravel {
			extractLaravelRoutes(file, root, apiPrefix, routes)
		}

		if found.symfony {
			if attributes := extractSymfonyRoutes(file.tokens, routes); len(attributes) > 0 {
				symfonyAttributes[file.path] = attributes
			}

			extractSymfonyLegacyRoutes(file, root, found.fosRest, routes)
			if found.apiPlatform {
				extractAPIPlatformRoutes(file.tokens, routes)
			}
		}

		if found.slim {
			extractSlimRoutes(file.tokens, routes)
		}
	})
	if err != nil {
		return nil, err
	}

	if found.symfony {
		imported := extractSymfonyConfigRoutes(root, symfonyAttributes, routes)
		addUnimportedSymfonyAttributes(symfonyAttributes, imported, routes)
		extractSymfonyLegacyConfigRoutes(root, routes)
	}

	return routes.sorted(), nil
}

func addUnimportedSymfonyAttributes(attributes map[string][]string, imported map[string]struct{}, routes routeSet) {
	for file, paths := range attributes {
		if _, ok := imported[file]; ok {
			continue
		}
		for _, path := range paths {
			routes.add(path)
		}
	}
}
