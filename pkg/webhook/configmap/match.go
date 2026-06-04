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

// MatchInput is the pod/process data evaluated against a K8sSelector.
type MatchInput struct {
	Namespace string
	// OwnerChain is the resolved ownership chain for the pod (e.g. ReplicaSet → Deployment).
	// The selector's OwnerKinds/OwnerNames are checked against the links in the chain.
	OwnerChain  []Owner
	Labels      map[string]string
	Annotations map[string]string
}

// Match reports whether the given input satisfies all populated selector fields.
// An empty or unset field is a wildcard.
func (s K8sSelector) Match(in MatchInput) bool {
	return s.matchNamespace(in.Namespace) &&
		s.matchOwner(in.OwnerChain) &&
		matchAllGlobs(s.PodLabels, in.Labels) &&
		matchAllGlobs(s.PodAnnotations, in.Annotations)
}

// matchNamespace reports whether the namespace matches any entry (OR);
// empty = all namespaces.
func (s K8sSelector) matchNamespace(namespace string) bool {
	if len(s.Namespaces) == 0 {
		return true
	}
	return slices.ContainsFunc(s.Namespaces, func(g services.GlobAttr) bool {
		return g.MatchString(namespace)
	})
}

// matchOwner reports whether some single owner-chain link satisfies both the
// OwnerKinds and OwnerNames constraints (kind ∈ OwnerKinds AND name matches some
// OwnerNames glob). Within each list entries are OR'd; an empty list leaves that
// dimension unconstrained, and both empty means no owner constraint at all.
func (s K8sSelector) matchOwner(chain []Owner) bool {
	if len(s.OwnerKinds) == 0 && len(s.OwnerNames) == 0 {
		return true
	}
	return slices.ContainsFunc(chain, func(o Owner) bool {
		return s.kindMatches(o.Kind) && s.nameMatches(o.Name)
	})
}

// kindMatches reports whether kind equals any OwnerKinds entry (OR);
// empty OwnerKinds = any kind.
func (s K8sSelector) kindMatches(kind string) bool {
	if len(s.OwnerKinds) == 0 {
		return true
	}
	return slices.Contains(s.OwnerKinds, kind)
}

// nameMatches reports whether name matches any OwnerNames glob (OR);
// empty OwnerNames = any name.
func (s K8sSelector) nameMatches(name string) bool {
	if len(s.OwnerNames) == 0 {
		return true
	}
	return slices.ContainsFunc(s.OwnerNames, func(g services.GlobAttr) bool {
		return g.MatchString(name)
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
