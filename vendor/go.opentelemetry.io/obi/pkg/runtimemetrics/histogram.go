// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics // import "go.opentelemetry.io/obi/pkg/runtimemetrics"

import (
	"errors"
	"fmt"
	"math"
)

const (
	timeHistogramMinBucketBits = 9
	timeHistogramMaxBucketBits = 48
	timeHistogramSubBucketBits = 2
	timeHistogramNumSubBuckets = 1 << timeHistogramSubBucketBits
	timeHistogramNumBuckets    = timeHistogramMaxBucketBits - timeHistogramMinBucketBits + 1
	timeHistogramTotalBuckets  = timeHistogramNumBuckets*timeHistogramNumSubBuckets + 2
)

// GoRuntimeHistogramData is an exporter-neutral explicit histogram in seconds.
type GoRuntimeHistogramData struct {
	Bounds       []float64
	BucketCounts []uint64
	Count        uint64
	// Sum is a lower-bound estimate that treats underflow as zero and includes
	// overflow at its finite lower bound.
	Sum float64
}

// Data converts a Go runtime histogram snapshot into independent exporter data.
func (snapshot GoRuntimeHistogramSnapshot) Data() (GoRuntimeHistogramData, error) {
	bucketCounts, count, err := otlpBucketCounts(snapshot)
	if err != nil {
		return GoRuntimeHistogramData{}, err
	}

	return GoRuntimeHistogramData{
		Bounds:       bucketBoundsSeconds(),
		BucketCounts: bucketCounts,
		Count:        count,
		Sum:          estimateSum(snapshot),
	}, nil
}

func runtimeHistogramBoundariesSeconds() [timeHistogramTotalBuckets + 1]float64 {
	var boundaries [timeHistogramTotalBuckets + 1]float64
	boundaries[0] = math.Inf(-1)

	for subBucket := 0; subBucket < timeHistogramNumSubBuckets; subBucket++ {
		bucketNanos := uint64(subBucket) << (timeHistogramMinBucketBits - 1 - timeHistogramSubBucketBits)
		boundaries[subBucket+1] = float64(bucketNanos) / 1e9
	}
	for bucketBit := timeHistogramMinBucketBits; bucketBit < timeHistogramMaxBucketBits; bucketBit++ {
		for subBucket := 0; subBucket < timeHistogramNumSubBuckets; subBucket++ {
			bucketNanos := uint64(1) << (bucketBit - 1)
			bucketNanos |= uint64(subBucket) << (bucketBit - 1 - timeHistogramSubBucketBits)
			bucketIndex := (bucketBit-timeHistogramMinBucketBits+1)*timeHistogramNumSubBuckets + subBucket + 1
			boundaries[bucketIndex] = float64(bucketNanos) / 1e9
		}
	}

	boundaries[len(boundaries)-2] = float64(uint64(1)<<(timeHistogramMaxBucketBits-1)) / 1e9
	boundaries[len(boundaries)-1] = math.Inf(1)
	return boundaries
}

func bucketBoundsSeconds() []float64 {
	runtimeBounds := runtimeHistogramBoundariesSeconds()
	bounds := make([]float64, len(runtimeBounds)-2)
	for i := range bounds {
		bounds[i] = math.Nextafter(runtimeBounds[i+1], runtimeBounds[i])
	}
	return bounds
}

func otlpBucketCounts(snapshot GoRuntimeHistogramSnapshot) ([]uint64, uint64, error) {
	if len(snapshot.Counts) != goRuntimeHistogramMaxBuckets {
		return nil, 0, fmt.Errorf(
			"invalid Go runtime histogram population count %d (want %d)",
			len(snapshot.Counts),
			goRuntimeHistogramMaxBuckets,
		)
	}

	bucketCounts := make([]uint64, len(snapshot.Counts)+2)
	bucketCounts[0] = snapshot.Underflow
	copy(bucketCounts[1:], snapshot.Counts)
	bucketCounts[len(bucketCounts)-1] = snapshot.Overflow

	var count uint64
	for _, population := range bucketCounts {
		if math.MaxUint64-count < population {
			return nil, 0, errors.New("go runtime histogram count overflow")
		}
		count += population
	}
	return bucketCounts, count, nil
}

func estimateSum(snapshot GoRuntimeHistogramSnapshot) float64 {
	runtimeBounds := runtimeHistogramBoundariesSeconds()
	var sum float64
	for i, population := range snapshot.Counts {
		sum += float64(population) * runtimeBounds[i+1]
	}
	return sum + float64(snapshot.Overflow)*runtimeBounds[len(runtimeBounds)-2]
}
