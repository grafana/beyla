// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ec2 // import "go.opentelemetry.io/contrib/detectors/aws/ec2"

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

type config struct {
	c Client
}

// newConfig returns an appropriately configured config.
func newConfig(options ...Option) *config {
	c := new(config)
	for _, option := range options {
		option.apply(c)
	}

	return c
}

// Option applies an EC2 detector configuration option.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (fn optionFunc) apply(c *config) {
	fn(c)
}

// WithClient sets the ec2metadata client in config.
func WithClient(t Client) Option {
	return optionFunc(func(c *config) {
		c.c = t
	})
}

func (cfg *config) getClient() Client {
	return cfg.c
}

// resource detector collects resource information from EC2 environment.
type resourceDetector struct {
	c Client
}

// Client implements methods to capture EC2 environment metadata information.
type Client interface {
	Available() bool
	GetInstanceIdentityDocument() (ec2metadata.EC2InstanceIdentityDocument, error)
	GetMetadata(p string) (string, error)
}

// compile time assertion that resourceDetector implements the resource.Detector interface.
var _ resource.Detector = (*resourceDetector)(nil)

// NewResourceDetector returns a resource detector that will detect AWS EC2 resources.
func NewResourceDetector(opts ...Option) resource.Detector {
	c := newConfig(opts...)
	return &resourceDetector{c.getClient()}
}

// Detect detects associated resources when running in AWS environment.
func (detector *resourceDetector) Detect(ctx context.Context) (*resource.Resource, error) {
	client, err := detector.client()
	if err != nil {
		return nil, err
	}

	if !client.Available() {
		return nil, nil
	}

	doc, err := client.GetInstanceIdentityDocument()
	if err != nil {
		return nil, err
	}

	attributes := []attribute.KeyValue{
		semconv.CloudProviderAWS,
		semconv.CloudPlatformAWSEC2,
		semconv.CloudRegion(doc.Region),
		semconv.CloudAvailabilityZone(doc.AvailabilityZone),
		semconv.CloudAccountID(doc.AccountID),
		semconv.HostID(doc.InstanceID),
		semconv.HostImageID(doc.ImageID),
		semconv.HostType(doc.InstanceType),
	}

	m := &metadata{client: client}
	m.add(semconv.HostNameKey, "hostname")

	attributes = append(attributes, m.attributes...)

	if len(m.errs) > 0 {
		err = fmt.Errorf("%w: %s", resource.ErrPartialResource, m.errs)
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attributes...), err
}

func (detector *resourceDetector) client() (Client, error) {
	if detector.c != nil {
		return detector.c, nil
	}

	s, err := session.NewSession()
	if err != nil {
		return nil, err
	}

	return ec2metadata.New(s), nil
}

type metadata struct {
	client     Client
	errs       []error
	attributes []attribute.KeyValue
}

func (m *metadata) add(k attribute.Key, n string) {
	v, err := m.client.GetMetadata(n)
	if err == nil {
		m.attributes = append(m.attributes, k.String(v))
		return
	}

	var rf awserr.RequestFailure
	ok := errors.As(err, &rf)
	if !ok {
		m.errs = append(m.errs, fmt.Errorf("%q: %w", n, err))
		return
	}

	if rf.StatusCode() == http.StatusNotFound {
		return
	}

	m.errs = append(m.errs, fmt.Errorf("%q: %d %s", n, rf.StatusCode(), rf.Code()))
}
