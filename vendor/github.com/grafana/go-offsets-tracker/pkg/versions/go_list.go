package versions

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/grafana/go-offsets-tracker/pkg/utils"
)

type goListResponse struct {
	Path     string   `json:"Path"`
	Versions []string `json:"versions"`
}

func FindVersionsUsingGoList(moduleName string) ([]string, error) {
	stdout, err := utils.RunCommand(fmt.Sprintf("go list -m -mod=readonly -json -versions %s", moduleName), "")
	if err != nil {
		log.Println("error running go list:\n", stdout)
		return nil, err
	}

	resp := goListResponse{}
	err = json.Unmarshal([]byte(stdout), &resp)
	if err != nil {
		return nil, err
	}

	return resp.Versions, nil
}
