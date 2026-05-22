package configmap

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
	// Namespaces: any must match (OR), empty = all namespaces
	if len(s.Namespaces) > 0 {
		matched := false
		for i := range s.Namespaces {
			if s.Namespaces[i].MatchString(in.Namespace) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// OwnerName + OwnerKind: any link in the chain must satisfy both (OR across chain)
	if s.OwnerName.IsSet() || s.OwnerKind != "" {
		matched := false
		for _, o := range in.OwnerChain {
			kindOK := s.OwnerKind == "" || s.OwnerKind == o.Kind
			nameOK := s.OwnerName.MatchString(o.Name)
			if kindOK && nameOK {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// PodLabels: all must match (AND), empty = all pods
	for k, g := range s.PodLabels {
		val, ok := in.Labels[k]
		if !ok || !g.MatchString(val) {
			return false
		}
	}

	// PodAnnotations: all must match (AND), empty = all pods
	for k, g := range s.PodAnnotations {
		val, ok := in.Annotations[k]
		if !ok || !g.MatchString(val) {
			return false
		}
	}

	return true
}
