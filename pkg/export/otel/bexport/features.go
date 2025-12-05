package bexport

import (
	"go.opentelemetry.io/obi/pkg/export"
)

// we reserve our own space for Beyla-specific custom features.
// To not collide with OBI features, we start reserving positions
// at the most significant bit
const (
	FeatureSurveyInfo = export.Features((1 << 63) >> iota)
	FeatureProcess
)

func init() {
	export.AppO11yFeatures |= FeatureProcess
	export.FeatureMapper["application_process"] = FeatureProcess
	export.FeatureMapper["survey_info"] = FeatureSurveyInfo
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
