// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package logenricher // import "go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"

import (
	"bytes"
	"encoding/json"
	"errors"

	"go.opentelemetry.io/obi/pkg/config"
)

type logFormatter struct {
	fieldNames       config.LogEnricherFieldNames
	plainText        config.LogEnricherPlainTextConfig
	traceFieldPrefix []byte
	spanFieldPrefix  []byte
}

func newLogFormatter(cfg config.LogEnricherConfig) logFormatter {
	return logFormatter{
		fieldNames:       cfg.FieldNames,
		plainText:        cfg.PlainText,
		traceFieldPrefix: []byte(cfg.FieldNames.TraceID + "="),
		spanFieldPrefix:  []byte(cfg.FieldNames.SpanID + "="),
	}
}

func (f logFormatter) format(logLine []byte, traceID, spanID string, includeSpan bool) ([]byte, error) {
	var fields map[string]any
	if err := json.Unmarshal(logLine, &fields); err == nil {
		if fields == nil {
			return logLine, nil
		}

		applyTraceContext(fields, f.fieldNames, traceID, spanID, includeSpan)

		out, err := json.Marshal(fields)
		if err != nil {
			return logLine, err
		}
		return append(out, '\n'), nil
	} else {
		var unmarshalTypeError *json.UnmarshalTypeError
		if errors.As(err, &unmarshalTypeError) {
			return logLine, nil
		}
	}

	if out, ok, err := f.formatNDJSON(logLine, traceID, spanID, includeSpan); ok || err != nil {
		return out, err
	}

	return f.formatPlainText(logLine, traceID, spanID, includeSpan), nil
}

func (f logFormatter) formatNDJSON(logLine []byte, traceID, spanID string, includeSpan bool) ([]byte, bool, error) {
	out := make([]byte, 0, len(logLine))
	records := 0

	for start := 0; start < len(logLine); {
		newline := bytes.IndexByte(logLine[start:], '\n')
		lineEnd := len(logLine)
		if newline >= 0 {
			lineEnd = start + newline
		}
		nextLine := lineEnd
		if newline >= 0 {
			nextLine++
		}

		contentEnd := lineEnd
		if contentEnd > start && logLine[contentEnd-1] == '\r' {
			contentEnd--
		}
		line := logLine[start:contentEnd]
		if len(bytes.TrimSpace(line)) != 0 {
			records++
			if !json.Valid(line) {
				return nil, false, nil
			}

			var fields map[string]any
			if err := json.Unmarshal(line, &fields); err == nil && fields != nil {
				applyTraceContext(fields, f.fieldNames, traceID, spanID, includeSpan)

				encoded, err := json.Marshal(fields)
				if err != nil {
					return nil, false, err
				}
				out = append(out, encoded...)
			} else {
				out = append(out, line...)
			}
		} else {
			out = append(out, line...)
		}

		out = append(out, logLine[contentEnd:nextLine]...)
		start = nextLine
	}

	if records < 2 {
		return nil, false, nil
	}

	return out, true, nil
}

func applyTraceContext(
	fields map[string]any,
	fieldNames config.LogEnricherFieldNames,
	traceID, spanID string,
	includeSpan bool,
) {
	if _, present := fields[fieldNames.TraceID]; !present {
		fields[fieldNames.TraceID] = traceID
	}

	if !includeSpan {
		return
	}

	if _, present := fields[fieldNames.SpanID]; !present {
		fields[fieldNames.SpanID] = spanID
	}
}

type lineAnnotation struct {
	start    int
	end      int
	addTrace bool
	addSpan  bool
}

func (f logFormatter) formatPlainText(logLine []byte, traceID, spanID string, includeSpan bool) []byte {
	if !f.plainText.Enabled {
		return logLine
	}

	annotations := f.annotations(logLine, includeSpan)
	if len(annotations) == 0 {
		return logLine
	}

	outputSize := len(logLine)
	for _, annotation := range annotations {
		outputSize += f.annotationSize(annotation, traceID, spanID)
	}

	out := make([]byte, 0, outputSize)
	cursor := 0
	for _, annotation := range annotations {
		out = append(out, logLine[cursor:annotation.start]...)
		if f.plainText.Placement == config.LogEnricherPlacementPrefix {
			out = f.appendFields(out, annotation, traceID, spanID)
			out = append(out, ' ')
			out = append(out, logLine[annotation.start:annotation.end]...)
		} else {
			out = append(out, logLine[annotation.start:annotation.end]...)
			out = append(out, ' ')
			out = f.appendFields(out, annotation, traceID, spanID)
		}
		cursor = annotation.end
	}

	return append(out, logLine[cursor:]...)
}

func (f logFormatter) annotations(logLine []byte, includeSpan bool) []lineAnnotation {
	switch f.plainText.Multiline {
	case config.LogEnricherMultilineFirstLine:
		var annotation []lineAnnotation
		visitPhysicalLines(logLine, func(start, end int) bool {
			if start == end {
				return true
			}
			if candidate, ok := f.annotation(logLine, start, end, includeSpan); ok {
				annotation = append(annotation, candidate)
			}
			return false
		})
		return annotation
	case config.LogEnricherMultilineLastLine:
		var last lineAnnotation
		var found bool
		visitPhysicalLines(logLine, func(start, end int) bool {
			if start != end {
				last, found = f.annotation(logLine, start, end, includeSpan)
			}
			return true
		})
		if found {
			return []lineAnnotation{last}
		}
		return nil
	case config.LogEnricherMultilineEachLine:
		var annotations []lineAnnotation
		visitPhysicalLines(logLine, func(start, end int) bool {
			if start == end {
				return true
			}
			if annotation, ok := f.annotation(logLine, start, end, includeSpan); ok {
				annotations = append(annotations, annotation)
			}
			return true
		})
		return annotations
	default:
		return nil
	}
}

func (f logFormatter) annotation(logLine []byte, start, end int, includeSpan bool) (lineAnnotation, bool) {
	line := logLine[start:end]
	annotation := lineAnnotation{
		start:    start,
		end:      end,
		addTrace: !hasField(line, f.traceFieldPrefix),
		addSpan:  includeSpan && !hasField(line, f.spanFieldPrefix),
	}
	return annotation, annotation.addTrace || annotation.addSpan
}

func (f logFormatter) annotationSize(annotation lineAnnotation, traceID, spanID string) int {
	size := 1
	if annotation.addTrace {
		size += len(f.traceFieldPrefix) + len(traceID)
	}
	if annotation.addSpan {
		if annotation.addTrace {
			size++
		}
		size += len(f.spanFieldPrefix) + len(spanID)
	}
	return size
}

func (f logFormatter) appendFields(out []byte, annotation lineAnnotation, traceID, spanID string) []byte {
	if annotation.addTrace {
		out = append(out, f.traceFieldPrefix...)
		out = append(out, traceID...)
	}
	if annotation.addSpan {
		if annotation.addTrace {
			out = append(out, ' ')
		}
		out = append(out, f.spanFieldPrefix...)
		out = append(out, spanID...)
	}
	return out
}

func visitPhysicalLines(logLine []byte, visit func(start, end int) bool) {
	for start := 0; start < len(logLine); {
		newline := bytes.IndexByte(logLine[start:], '\n')
		if newline < 0 {
			visit(start, len(logLine))
			return
		}

		newline += start
		end := newline
		if end > start && logLine[end-1] == '\r' {
			end--
		}
		if !visit(start, end) {
			return
		}
		start = newline + 1
	}
}

func hasField(line, fieldPrefix []byte) bool {
	for i := 0; i+len(fieldPrefix) <= len(line); i++ {
		if i != 0 && !isASCIIWhitespace(line[i-1]) {
			continue
		}
		if bytes.HasPrefix(line[i:], fieldPrefix) {
			return true
		}
	}
	return false
}

func isASCIIWhitespace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}
