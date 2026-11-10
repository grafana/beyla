//go:build !(linux && beyla_nvml)

package gpu

import "errors"

var errNVMLNotBuilt = errors.New("NVIDIA GPU support requires building Beyla with the beyla_nvml build tag")

func discoverNVIDIA() ([]Device, error) { return nil, errNVMLNotBuilt }

func shutdownNVIDIA() {}
