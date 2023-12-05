# promwrite

Prometheus Remote Write Go client with minimal dependencies. Supports Prometheus, Cortex, VictoriaMetrics etc.

### Install

```
go get -u github.com/castai/promwrite
```

### Example Usage

```go
client := promwrite.NewClient("http://prometheus:8428/api/v1/write")
resp, err := client.Write(context.Background(), &promwrite.WriteRequest{
	TimeSeries: []promwrite.TimeSeries{
		{
			Labels: []promwrite.Label{
				{
					Name:  "__name__",
					Value: "my_metric_name",
				},
			},
			Sample: promwrite.Sample{
				Time:  time.Now(),
				Value: 123,
			},
		},
	},
})
```
