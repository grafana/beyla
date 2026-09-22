package bexport

import (
	"go.opentelemetry.io/obi/pkg/export"
)

// we reserve our own space for Beyla-specific custom features.
// To not collide with OBI features, we start reserving positions
// at the most significant bit
const (
	FeatureProcess = export.Features((1 << 63) >> iota)
	// FeatureHostInfo preserves application_host selection for Beyla-owned exporters.
	// Overrides OBI configuration for custom metric attributes
	FeatureHostInfo
)

func init() {
	export.AppO11yFeatures |= FeatureProcess | FeatureHostInfo
	export.FeatureMapper["application_process"] = FeatureProcess
}

// Has is added here for convenience, as features.Feature has already a Has
// method but it's private.
// It returns true if all the flags in checkingFlags are present in src
func Has(src, checkingFlags export.Features) bool {
	return src&checkingFlags == checkingFlags
}

// Any returns true if any of the flags in checkingFlags is present in src.
// It's added here for convenience, as features.Feature has already an Any
// method but it's private.
func Any(src, checkingFlags export.Features) bool {
	return src&checkingFlags != 0
}

// HostInfoFeatures transfers ownership of host-info metrics from OBI to Beyla.
// Keep a nonzero bit for host-only service rules so they do not inherit global defaults.
func HostInfoFeatures(f export.Features) export.Features {
	if f.AppHost() {
		return (f &^ export.FeatureApplicationHost) | FeatureHostInfo
	}
	return f
}
