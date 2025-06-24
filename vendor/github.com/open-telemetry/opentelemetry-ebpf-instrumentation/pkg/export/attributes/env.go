package attributes

import "strings"

type VarHandler func(k string, v string)

func ParseOTELResourceVariable(envVar string, handler VarHandler) {
	// split all the comma-separated key=value entries
	for _, entry := range strings.Split(envVar, ",") {
		// split only by the first '=' appearance, as values might
		// have base64 '=' padding symbols
		keyVal := strings.SplitN(entry, "=", 2)
		if len(keyVal) < 2 {
			continue
		}

		k := strings.TrimSpace(keyVal[0])
		v := strings.TrimSpace(keyVal[1])

		if k == "" || v == "" {
			continue
		}

		handler(strings.TrimSpace(keyVal[0]), strings.TrimSpace(keyVal[1]))
	}
}
