package versions

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	jsonUrl = "https://go.dev/dl/?mode=json&include=all"
)

type goDevResponse struct {
	Version string `json:"version"`
	Stable  bool   `json:"stable"`
}

func FindVersionsFromGoWebsite() ([]string, error) {
	res, err := http.Get(jsonUrl)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var resp []goDevResponse
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}

	var versions []string
	for _, v := range resp {
		if v.Stable {
			stripepdV := strings.ReplaceAll(v.Version, "go", "")
			versions = append(versions, stripepdV)
		}
	}

	return versions, nil
}
