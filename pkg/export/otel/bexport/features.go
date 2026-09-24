package bexport

import (
	"go.opentelemetry.io/obi/pkg/export"
)

// we reserve our own space for Beyla-specific custom features.
// To not collide with OBI features, we start reserving positions
// at the most significant bit
const (
	FeatureProcess = export.Features((1 << 63) >> iota)
	// FeatureHostInfo enables Beyla's traces_host_info metric.
	FeatureHostInfo
)

// Older OBI versions still own a host-info bit, also enabled by "all"/"*".
// TODO: This is zero once OBI PR #3556 removes the upstream feature.
var legacyOBIHostFeature = export.FeatureMapper["application_host"]

func init() {
	export.AppO11yFeatures |= FeatureProcess | FeatureHostInfo
	export.FeatureMapper["application_process"] = FeatureProcess
	export.FeatureMapper["application_host"] = FeatureHostInfo
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

// HostInfoFeatures disables the old OBI exporter when using a pre-#3556 dependency.
// Named application_host selections already use Beyla's bit; this also handles all/*.
// todo: Remove this compatibility guard after updating OBI past PR #3556.
func HostInfoFeatures(f export.Features) export.Features {
	if f&legacyOBIHostFeature != 0 {
		return (f &^ legacyOBIHostFeature) | FeatureHostInfo
	}
	return f
}
