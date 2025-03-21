package responses

import (
	"encoding/json"
	"fmt"
	"strconv"
)

func ParseQueryOutput(body []byte) ([]Result, error) {
	qr := QueryResult{}
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("decoding Prometheus response: %w", err)
	}

	return qr.Data.Result, nil
}

func EnoughPromResults(results []Result) error {
	if len(results) < 1 {
		return fmt.Errorf("prometheus query results must have at least 1 element")
	}

	return nil
}

func TotalPromCount(results []Result) (int, error) {
	total := 0
	for _, res := range results {
		if len(res.Value) < 2 {
			return 0, fmt.Errorf("result %v must have at least 2 elements", res)
		}

		val, err := strconv.Atoi(res.Value[1].(string))

		if err != nil {
			return 0, err
		}

		total += val
	}

	return total, nil
}
