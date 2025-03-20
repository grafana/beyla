package lint

import "fmt"

func NewPanelUnitsRule() *PanelRuleFunc {
	validUnits := []string{
		// Enumerated from: https://github.com/grafana/grafana/blob/main/packages/grafana-data/src/valueFormats/categories.ts
		// Scalar, e.g. number of loaded classes
		"none",
		// Misc
		"string",
		// short
		"short", "percent", "percentunit", "humidity", "dB", "hex0x", "hex", "sci", "locale", "pixel",
		// Acceleration
		"accMS2", "accFS2", "accG",
		// Angle
		"degree", "radian", "grad", "arcmin", "arcsec",
		// Area
		"areaM2", "areaF2", "areaMI2",
		// Computation
		"flops", "mflops", "gflops", "tflops", "pflops", "eflops", "zflops", "yflops",
		// Concentration
		"ppm", "conppb", "conngm3", "conngNm3", "conμgm3", "conμgNm3", "conmgm3", "conmgNm3", "congm3", "congNm3", "conmgdL", "conmmolL",
		// Currency
		"currencyUSD", "currencyGBP", "currencyEUR", "currencyJPY", "currencyRUB", "currencyUAH", "currencyBRL", "currencyDKK", "currencyISK", "currencyNOK", "currencySEK", "currencyCZK", "currencyCHF", "currencyPLN", "currencyBTC", "currencymBTC", "currencyμBTC", "currencyZAR", "currencyINR", "currencyKRW", "currencyIDR", "currencyPHP", "currencyVND",
		// Data
		"bytes", "decbytes", "bits", "decbits", "kbytes", "deckbytes", "mbytes", "decmbytes", "gbytes", "decgbytes", "tbytes", "dectbytes", "pbytes", "decpbytes",
		// Data rate
		"pps", "binBps", "Bps", "binbps", "bps", "KiBs", "Kibits", "KBs", "Kbits", "MiBs", "Mibits", "MBs", "Mbits", "GiBs", "Gibits", "GBs", "Gbits", "TiBs", "Tibits", "TBs", "Tbits", "PiBs", "Pibits", "PBs", "Pbits",
		// Date & time
		"dateTimeAsIso", "dateTimeAsIsoNoDateIfToday", "dateTimeAsUS", "dateTimeAsUSNoDateIfToday", "dateTimeAsLocal",
		// Datetime local (No date if today)
		"dateTimeAsLocalNoDateIfToday", "dateTimeAsSystem", "dateTimeFromNow",
		// Energy
		"watt", "kwatt", "megwatt", "gwatt", "mwatt", "Wm2", "voltamp", "kvoltamp", "voltampreact", "kvoltampreact", "watth", "watthperkg", "kwatth", "kwattm", "amph", "kamph", "mamph", "joule", "ev", "amp", "kamp", "mamp", "volt", "kvolt", "mvolt", "dBm", "ohm", "kohm", "Mohm", "farad", "µfarad", "nfarad", "pfarad", "ffarad", "henry", "mhenry", "µhenry", "lumens",
		// Flow
		"flowgpm", "flowcms", "flowcfs", "flowcfm", "litreh", "flowlpm", "flowmlpm", "lux",
		// Force
		"forceNm", "forcekNm", "forceN", "forcekN",
		// Hash rate
		"Hs", "KHs", "MHs", "GHs", "THs", "PHs", "EHs",
		// Mass
		"massmg", "massg", "masslb", "masskg", "masst",
		// Length
		"lengthmm", "lengthin", "lengthft", "lengthm", "lengthkm", "lengthmi",
		// Pressure
		"pressurembar", "pressurebar", "pressurekbar", "pressurepa", "pressurehpa", "pressurekpa", "pressurehg", "pressurepsi",
		// Radiation
		"radbq", "radci", "radgy", "radrad", "radsv", "radmsv", "radusv", "radrem", "radexpckg", "radr", "radsvh", "radmsvh", "radusvh",
		// Rotational Speed
		"rotrpm", "rothz", "rotrads", "rotdegs",
		// Temperature
		"celsius", "fahrenheit", "kelvin",
		// Time
		"hertz", "ns", "µs", "ms", "s", "m", "h", "d", "dtdurationms", "dtdurations", "dthms", "dtdhms", "timeticks", "clockms", "clocks",
		// Throughput
		"cps", "ops", "reqps", "rps", "wps", "iops", "cpm", "opm", "rpm", "wpm",
		// Velocity
		"velocityms", "velocitykmh", "velocitymph", "velocityknot",
		// Volume
		"mlitre", "litre", "m3", "Nm3", "dm3", "gallons",
		// Boolean
		"bool", "bool_yes_no", "bool_on_off",
	}

	return &PanelRuleFunc{
		name:        "panel-units-rule",
		description: "Checks that each panel uses has valid units defined.",
		fn: func(d Dashboard, p Panel) PanelRuleResults {
			r := PanelRuleResults{}
			switch p.Type {
			case panelTypeStat, panelTypeSingleStat, panelTypeGraph, panelTypeTimeTable, panelTypeTimeSeries, panelTypeGauge:
				configuredUnit := getConfiguredUnit(p)
				if configuredUnit != "" {
					for _, u := range validUnits {
						if u == p.FieldConfig.Defaults.Unit {
							return r
						}
					}
				}
				r.AddError(d, p, fmt.Sprintf("has no or invalid units defined: '%s'", configuredUnit))
			}
			return r
		},
	}
}

func getConfiguredUnit(p Panel) string {
	configuredUnit := ""
	// First check if an override with unit exists - if no override then check if standard unit is present and valid
	if p.FieldConfig != nil && len(p.FieldConfig.Overrides) > 0 {
		for _, p := range p.FieldConfig.Overrides {
			for _, o := range p.OverrideProperties {
				if o.Id == "unit" {
					configuredUnit = o.Value
				}
			}
		}
	}
	if configuredUnit == "" && p.FieldConfig != nil && len(p.FieldConfig.Defaults.Unit) > 0 {
		configuredUnit = p.FieldConfig.Defaults.Unit
	}
	return configuredUnit
}
