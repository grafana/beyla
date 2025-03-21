package lint

import (
	"fmt"

	"github.com/prometheus/prometheus/model/labels"
)

func checkForMatcher(selector []*labels.Matcher, name string, ty labels.MatchType, value string) error {
	for _, matcher := range selector {
		if matcher.Name != name {
			continue
		}

		if matcher.Type != ty {
			return fmt.Errorf("%s selector is %s, not %s", name, matcher.Type, ty)
		}

		if matcher.Value != value {
			return fmt.Errorf("%s selector is %s, not %s", name, matcher.Value, value)
		}

		return nil
	}

	return fmt.Errorf("%s selector not found", name)
}
