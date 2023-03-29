package versions

import (
	"encoding/json"
	"fmt"
	"github.com/grafana/go-offsets-tracker/pkg/utils"
)

type goListResponse struct {
	Path     string   `json:"Path"`
	Versions []string `json:"versions"`
}

func FindVersionsUsingGoList(moduleName string) ([]string, error) {
	err, stdout, _ := utils.RunCommand(fmt.Sprintf("go list -m -mod=readonly -json -versions %s", moduleName), "")
	if err != nil {
		return nil, err
	}

	resp := goListResponse{}
	err = json.Unmarshal([]byte(stdout), &resp)
	if err != nil {
		return nil, err
	}

	return resp.Versions, nil
}
