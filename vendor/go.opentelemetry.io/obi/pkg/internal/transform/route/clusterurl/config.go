// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package clusterurl // import "go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl"

import "errors"

type Config struct {
	// MaxSegments is the maximum number of segments in a path.
	MaxSegments int `json:"max_segments"`
	// Separator is the character that separates segments in a path.
	Separator byte `json:"separator"`
	// ReplaceWith is the character that will replace the segments in a path.
	ReplaceWith byte `json:"replace_with"`
	// CacheSize is the size of the cache for the classifier.
	CacheSize int `json:"cache_size"`
	// ModelPath is the path to the model file.
	ModelPath string `json:"model_path"`
}

func DefaultConfig() *Config {
	return &Config{
		MaxSegments: 10,
		Separator:   '/',
		ReplaceWith: '*',
		CacheSize:   8192,
		ModelPath:   "",
	}
}

func (c *Config) Validate() error {
	if c.MaxSegments <= 0 {
		return errors.New("field MaxSegments must be greater than 0")
	}
	if c.Separator == 0 {
		return errors.New("field Separator cannot be zero")
	}
	if c.ReplaceWith == 0 {
		return errors.New("field ReplaceWith cannot be zero")
	}
	if c.CacheSize <= 0 {
		return errors.New("field CacheSize must be greater than 0")
	}
	if c.MaxSegments > 100 {
		return errors.New("field MaxSegments cannot be greater than 100")
	}
	return nil
}
