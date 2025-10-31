package arg

import "net/http"

const (
	// Delay allows delaying the response of a service call (default: no delay)
	Delay = "delay"
	// Status allows specifying the status response of a service call (default: 200)
	Status        = "status"
	DefaultStatus = http.StatusOK
)
