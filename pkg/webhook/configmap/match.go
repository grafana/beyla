package configmap

import (
	"slices"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// Owner is a single link in a pod's ownership chain (e.g. ReplicaSet, Deployment).
type Owner struct {
	Name string
	Kind string
}

// MatchInput is the pod/process data evaluated against a Selector.
type MatchInput struct {
	Namespace string
	// OwnerChain is the resolved ownership chain for the pod (e.g. ReplicaSet → Deployment).
	// The selector's OwnerName/OwnerKind are checked against any link in the chain (OR semantics).
	OwnerChain  []Owner
	Labels      map[string]string
	Annotations map[string]string
}

// Match reports whether the given input satisfies all populated selector fields.
// An empty or unset field is a wildcard.
func (s Selector) Match(in MatchInput) bool {
	return s.matchNamespace(in.Namespace) &&
		s.matchOwner(in.OwnerChain) &&
		matchAllGlobs(s.PodLabels, in.Labels) &&
		matchAllGlobs(s.PodAnnotations, in.Annotations)
}

// matchNamespace reports whether the namespace matches any entry (OR);
// empty = all namespaces.
func (s Selector) matchNamespace(namespace string) bool {
	if len(s.Namespaces) == 0 {
		return true
	}
	return slices.ContainsFunc(s.Namespaces, func(g services.GlobAttr) bool {
		return g.MatchString(namespace)
	})
}

// matchOwner reports whether any link in the chain satisfies both OwnerName and
// OwnerKind (OR across chain); unset name and empty kind = any owner.
func (s Selector) matchOwner(chain []Owner) bool {
	if !s.OwnerName.IsSet() && s.OwnerKind == "" {
		return true
	}
	return slices.ContainsFunc(chain, func(o Owner) bool {
		return (s.OwnerKind == "" || s.OwnerKind == o.Kind) && s.OwnerName.MatchString(o.Name)
	})
}

// matchAllGlobs reports whether every key in globs has a matching value (AND);
// empty globs = match anything.
func matchAllGlobs(globs map[string]services.GlobAttr, values map[string]string) bool {
	for k, g := range globs {
		val, ok := values[k]
		if !ok || !g.MatchString(val) {
			return false
		}
	}
	return true
}
