// Copyright Sam Xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelsql

import (
	"context"
	"database/sql/driver"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	internalsemconv "github.com/XSAM/otelsql/internal/semconv"
)

const (
	instrumentationName = "github.com/XSAM/otelsql"
)

var (
	connectionStatusKey = attribute.Key("status")
	queryStatusKey      = attribute.Key("status")
	queryMethodKey      = attribute.Key("method")
)

// SpanNameFormatter supports formatting span names.
type SpanNameFormatter func(ctx context.Context, method Method, query string) string

// AttributesGetter provides additional attributes on spans creation.
type AttributesGetter func(ctx context.Context, method Method, query string, args []driver.NamedValue) []attribute.KeyValue

// InstrumentAttributesGetter provides additional attributes while recording metrics to instruments.
type InstrumentAttributesGetter func(ctx context.Context, method Method, query string, args []driver.NamedValue) []attribute.KeyValue

// InstrumentErrorAttributesGetter provides additional error-related attributes while recording metrics to instruments.
type InstrumentErrorAttributesGetter func(err error) []attribute.KeyValue

// SpanFilter is a function that determines whether a span should be created for a given SQL operation.
// It returns true if the span should be created, or false to skip span creation.
type SpanFilter func(ctx context.Context, method Method, query string, args []driver.NamedValue) bool

type config struct {
	TracerProvider trace.TracerProvider
	Tracer         trace.Tracer

	MeterProvider metric.MeterProvider
	Meter         metric.Meter

	Instruments *instruments

	SpanOptions SpanOptions

	// Attributes will be set to each span and measurement.
	Attributes []attribute.KeyValue

	// SpanNameFormatter will be called to produce span's name.
	// Default use method as span name
	SpanNameFormatter SpanNameFormatter

	// SQLCommenterEnabled enables context propagation for database
	// by injecting a comment into SQL statements.
	//
	// Experimental
	//
	// Notice: This config is EXPERIMENTAL and may be changed or removed in a
	// later release.
	SQLCommenterEnabled bool
	SQLCommenter        *commenter
	TextMapPropagator   propagation.TextMapPropagator

	// AttributesGetter will be called to produce additional attributes while creating spans.
	// Default returns nil
	AttributesGetter AttributesGetter

	// InstrumentAttributesGetter will be called to produce additional attributes while recording metrics to instruments.
	// Default returns nil
	InstrumentAttributesGetter InstrumentAttributesGetter

	InstrumentErrorAttributesGetter InstrumentErrorAttributesGetter

	// DisableSkipErrMeasurement, if set to true, will suppress driver.ErrSkip as an error status in metrics.
	// The metric measurement will be recorded as status=ok.
	// Default is false
	DisableSkipErrMeasurement bool

	// SemConvStabilityOptIn controls which database semantic convention are emitted.
	// It follows the value of environment variable `OTEL_SEMCONV_STABILITY_OPT_IN`.
	SemConvStabilityOptIn internalsemconv.OTelSemConvStabilityOptInType

	// DBQueryTextAttributes will be called to produce related attributes on `db.query.text`.
	// It follows the value of environment variable `OTEL_SEMCONV_STABILITY_OPT_IN`.
	DBQueryTextAttributes func(query string) []attribute.KeyValue
}

// SpanOptions holds configuration of tracing span to decide
// whether to enable some features.
// By default all options are set to false intentionally when creating a wrapped
// driver and provide the most sensible default with both performance and
// security in mind.
type SpanOptions struct {
	// Ping, if set to true, will enable the creation of spans on Ping requests.
	Ping bool

	// RowsNext, if set to true, will enable the creation of events in spans on RowsNext
	// calls. This can result in many events.
	RowsNext bool

	// DisableErrSkip, if set to true, will suppress driver.ErrSkip errors in spans.
	DisableErrSkip bool

	// DisableQuery if set to true, will suppress db.statement in spans.
	DisableQuery bool

	// RecordError, if set, will be invoked with the current error, and if the func returns true
	// the record will be recorded on the current span.
	//
	// If this is not set it will default to record all errors (possible not ErrSkip, see option
	// DisableErrSkip).
	RecordError func(err error) bool

	// OmitConnResetSession if set to true will suppress sql.conn.reset_session spans
	OmitConnResetSession bool

	// OmitConnPrepare if set to true will suppress sql.conn.prepare spans
	OmitConnPrepare bool

	// OmitConnQuery if set to true will suppress sql.conn.query spans
	OmitConnQuery bool

	// OmitRows if set to true will suppress sql.rows spans
	OmitRows bool

	// OmitConnectorConnect if set to true will suppress sql.connector.connect spans
	OmitConnectorConnect bool

	// SpanFilter, if set, will be invoked before each call to create a span. If it returns
	// false, the span will not be created.
	SpanFilter SpanFilter
}

func defaultSpanNameFormatter(_ context.Context, method Method, _ string) string {
	return string(method)
}

// newConfig returns a config with all Options set.
func newConfig(options ...Option) config {
	cfg := config{
		TracerProvider:    otel.GetTracerProvider(),
		MeterProvider:     otel.GetMeterProvider(),
		SpanNameFormatter: defaultSpanNameFormatter,
		// Uses the stable behavior
		SemConvStabilityOptIn: internalsemconv.OTelSemConvStabilityOptInStable,
		DBQueryTextAttributes: internalsemconv.NewDBQueryTextAttributes(
			internalsemconv.OTelSemConvStabilityOptInStable,
		),
	}
	for _, opt := range options {
		opt.Apply(&cfg)
	}

	cfg.Tracer = cfg.TracerProvider.Tracer(
		instrumentationName,
		trace.WithInstrumentationVersion(Version()),
	)
	cfg.Meter = cfg.MeterProvider.Meter(
		instrumentationName,
		metric.WithInstrumentationVersion(Version()),
	)

	cfg.SQLCommenter = newCommenter(cfg.SQLCommenterEnabled, cfg.TextMapPropagator)

	var err error
	if cfg.Instruments, err = newInstruments(cfg.Meter); err != nil {
		otel.Handle(err)
	}

	// Initialize SemConvStabilityOptIn from environment
	cfg.SemConvStabilityOptIn = internalsemconv.ParseOTelSemConvStabilityOptIn()

	// Initialize DBQueryTextAttributes based on SemConvStabilityOptIn
	cfg.DBQueryTextAttributes = internalsemconv.NewDBQueryTextAttributes(cfg.SemConvStabilityOptIn)

	return cfg
}
