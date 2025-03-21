package responses

type QueryResult struct {
	Status string `json:"status"`
	Data   Data   `json:"data"`
}

type Data struct {
	Result     []Result `json:"result"`
	ResultType string   `json:"resultType"`
}

// Result structure assumes that resultType is always == "vector"
type Result struct {
	Metric map[string]string `json:"metric"`
	Value  []interface{}
}
