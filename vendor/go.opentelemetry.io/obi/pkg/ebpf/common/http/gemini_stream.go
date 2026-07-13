// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common/http"

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"strings"

	jsonpath "github.com/ohler55/ojg/jp"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

// maxGeminiStreamCandidates bounds allocations derived from response-provided
// candidate indices, consistent with the openai_stream.go guard.
const maxGeminiStreamCandidates = 256

// maxPartialArgArrayIndex bounds array indices in JSONPath expressions from
// partialArgs to prevent unbounded memory allocation from malformed paths.
const maxPartialArgArrayIndex = 1024

type geminiStreamChunk struct {
	Candidates    []geminiStreamCandidate `json:"candidates"`
	UsageMetadata *request.GeminiUsage    `json:"usageMetadata"`
	ModelVersion  string                  `json:"modelVersion"`
	ResponseID    string                  `json:"responseId"`
}

type geminiStreamCandidate struct {
	Index         int                  `json:"index"`
	Content       *geminiStreamContent `json:"content"`
	FinishReason  string               `json:"finishReason"`
	SafetyRatings json.RawMessage      `json:"safetyRatings,omitempty"`
}

type geminiStreamContent struct {
	Parts []json.RawMessage `json:"parts"`
	Role  string            `json:"role"`
}

// geminiStreamPart is a unified view of a single streamed content part. A part
// is either a text part (optionally a thought summary, optionally carrying a
// thoughtSignature) or a function-call part. The outer thoughtSignature applies
// to whichever kind the part is.
type geminiStreamPart struct {
	Text             string                  `json:"text"`
	Thought          bool                    `json:"thought"`
	ThoughtSignature string                  `json:"thoughtSignature"`
	FunctionCall     *geminiFunctionCallData `json:"functionCall"`
}

type geminiFunctionCallData struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
	// PartialArgs is intentionally a RawMessage because Vertex AI's
	// streamFunctionCallArguments feature sends it as an array of
	// {jsonPath, <typed value>} objects, while some observations use a plain
	// string fragment. Decoding into a concrete type would fail on the array
	// shape and drop the whole part, so we keep it raw and interpret it in
	// addPartialArgs.
	PartialArgs  json.RawMessage `json:"partialArgs,omitempty"`
	WillContinue *bool           `json:"willContinue,omitempty"`
}

// geminiStreamError represents a bare error envelope that Gemini may send on
// an HTTP 200 stream (as observed by the official Go client).
type geminiStreamError struct {
	Error *request.GeminiError `json:"error"`
}

// candidatePart is a single ordered part in a candidate's content.
// Either textBuilder is non-nil (text part) or fcRaw is non-nil (function-call part).
type candidatePart struct {
	textBuilder *strings.Builder
	thought     bool
	// signature holds the part's thoughtSignature. Signed parts must remain
	// distinct (Gemini requires signatures to stay on their exact parts and
	// says signed parts must not be merged).
	signature string
	fcRaw     json.RawMessage
}

// fcAggregator accumulates streaming function call arguments for Vertex AI's
// streamFunctionCallArguments feature where args arrive across multiple chunks.
type fcAggregator struct {
	name      string
	signature string
	// argsAccum accumulates string-fragment style partial args (legacy shape).
	argsAccum strings.Builder
	// argsObj reconstructs args from Vertex AI's {jsonPath, <typed value>}
	// partialArgs array elements.
	argsObj map[string]any
	// strFrags accumulates streamed string fragments per jsonPath. Vertex AI
	// splits a single string argument across multiple PartialArg elements that
	// share a jsonPath and set willContinue=true until the final fragment, so
	// the fragments must be concatenated rather than overwritten.
	strFrags   map[string]string
	hasFullArg bool            // true if args came as a complete JSON object
	fullArg    json.RawMessage // stored when args is a complete JSON object
}

// geminiPartialArg mirrors a single Vertex AI PartialArg element from the
// streamFunctionCallArguments feature. Each element targets a JSONPath within
// the reconstructed arguments object and carries exactly one typed value from
// the value union (stringValue / numberValue / boolValue / nullValue). A string
// value may be split across multiple elements sharing a jsonPath, with
// willContinue=true on every fragment except the last.
// See https://docs.cloud.google.com/vertex-ai/generative-ai/docs/reference/rpc/google.cloud.aiplatform.v1#partialarg
type geminiPartialArg struct {
	JSONPath     string          `json:"jsonPath"`
	StringValue  *string         `json:"stringValue"`
	NumberValue  *float64        `json:"numberValue"`
	BoolValue    *bool           `json:"boolValue"`
	NullValue    json.RawMessage `json:"nullValue"`
	WillContinue *bool           `json:"willContinue"`
}

// addPartialArgs interprets a raw partialArgs value, supporting both the
// Vertex AI array-of-objects shape ([{jsonPath, <typed value>}, ...]) and the
// plain string-fragment shape. Unknown shapes are ignored rather than fatal.
func (fc *fcAggregator) addPartialArgs(raw json.RawMessage) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return
	}
	switch trimmed[0] {
	case '"':
		// String-fragment shape: concatenate the decoded fragment.
		var frag string
		if err := json.Unmarshal(raw, &frag); err == nil {
			fc.argsAccum.WriteString(frag)
		}
	case '[':
		// Vertex AI array shape: each element carries a jsonPath and exactly
		// one typed value from the value union.
		var elems []geminiPartialArg
		if err := json.Unmarshal(raw, &elems); err != nil {
			return
		}
		for i := range elems {
			fc.applyPartialArg(&elems[i])
		}
	}
}

// applyPartialArg decodes one PartialArg's typed value and assigns it at the
// element's jsonPath. String values are accumulated per path across fragments
// (Vertex AI streams them with willContinue=true until the final fragment) so
// that a trailing empty terminator does not clobber the accumulated text; other
// typed values are assigned directly.
func (fc *fcAggregator) applyPartialArg(arg *geminiPartialArg) {
	if arg.JSONPath == "" {
		return
	}
	if fc.argsObj == nil {
		fc.argsObj = map[string]any{}
	}
	switch {
	case arg.StringValue != nil:
		if fc.strFrags == nil {
			fc.strFrags = map[string]string{}
		}
		acc := fc.strFrags[arg.JSONPath] + *arg.StringValue
		fc.strFrags[arg.JSONPath] = acc
		setByJSONPath(fc.argsObj, arg.JSONPath, acc)
		// Once the provider signals the fragment sequence is complete, drop
		// the per-path accumulator so a later argument at the same path starts
		// fresh.
		if arg.WillContinue == nil || !*arg.WillContinue {
			delete(fc.strFrags, arg.JSONPath)
		}
	case arg.NumberValue != nil:
		setByJSONPath(fc.argsObj, arg.JSONPath, *arg.NumberValue)
	case arg.BoolValue != nil:
		setByJSONPath(fc.argsObj, arg.JSONPath, *arg.BoolValue)
	case arg.NullValue != nil:
		setByJSONPath(fc.argsObj, arg.JSONPath, nil)
	}
}

// setByJSONPath assigns value at the given JSONPath within the target map,
// creating intermediate objects and arrays as needed. It reuses the shared
// github.com/ohler55/ojg/jp parser so array segments (e.g. "$.items[0].id")
// are handled per the Vertex AI contract instead of a hand-rolled dotted-key
// parser. Invalid paths are skipped rather than fatal.
func setByJSONPath(m map[string]any, path string, value any) {
	expr, err := jsonpath.ParseString(path)
	if err != nil {
		return
	}
	frags := stripRootFrags([]jsonpath.Frag(expr))
	if len(frags) == 0 {
		return
	}
	setAtFrags(m, frags, value)
}

// stripRootFrags drops the leading root ("$") or current-node ("@") markers
// from a parsed JSONPath so the remaining fragments describe the location
// relative to the target map.
func stripRootFrags(frags []jsonpath.Frag) []jsonpath.Frag {
	for len(frags) > 0 {
		switch frags[0].(type) {
		case jsonpath.Root, jsonpath.At:
			frags = frags[1:]
		default:
			return frags
		}
	}
	return frags
}

// setAtFrags recursively assigns value at the location described by frags
// within container, creating intermediate maps and arrays (including nested
// array elements) as needed. It returns the possibly reallocated container so
// callers can reattach a grown slice. Only plain object-key (Child) and array
// index (Nth) fragments are supported; other fragment kinds stop the descent.
func setAtFrags(container any, frags []jsonpath.Frag, value any) any {
	if len(frags) == 0 {
		return value
	}
	switch f := frags[0].(type) {
	case jsonpath.Child:
		m, ok := container.(map[string]any)
		if !ok || m == nil {
			m = map[string]any{}
		}
		key := string(f)
		m[key] = setAtFrags(m[key], frags[1:], value)
		return m
	case jsonpath.Nth:
		idx := int(f)
		if idx < 0 || idx >= maxPartialArgArrayIndex {
			return container
		}
		s, _ := container.([]any)
		for len(s) <= idx {
			s = append(s, nil)
		}
		s[idx] = setAtFrags(s[idx], frags[1:], value)
		return s
	default:
		return container
	}
}

// candidateAggregator accumulates streamed parts for a single candidate
// index, preserving the original part ordering.
type candidateAggregator struct {
	parts        []candidatePart
	finishReason string
	// safetyRatings preserves the raw safetyRatings block from the stream,
	// consistent with the non-streaming GeminiCandidate.SafetyRatings field.
	safetyRatings json.RawMessage
	// activeFC tracks a function call being built across multiple stream chunks
	// (Vertex AI streamFunctionCallArguments).
	activeFC *fcAggregator
}

// flushActiveFC finalizes any in-progress function call aggregation and
// appends the result to the candidate's parts list. Returns the function
// call name for toolCalls tracking (empty if nothing was flushed).
func (ca *candidateAggregator) flushActiveFC() string {
	if ca.activeFC == nil {
		return ""
	}
	fc := ca.activeFC
	ca.activeFC = nil

	if fc.name == "" {
		return ""
	}

	var raw json.RawMessage
	switch {
	case fc.hasFullArg:
		// Complete args arrived as a JSON object.
		raw = buildFunctionCallRaw(fc.name, fc.fullArg, fc.signature)
	case len(fc.argsObj) > 0:
		// Args reconstructed from Vertex AI partialArgs array elements.
		if b, err := json.Marshal(fc.argsObj); err == nil {
			raw = buildFunctionCallRaw(fc.name, b, fc.signature)
		} else {
			raw = buildFunctionCallRaw(fc.name, nil, fc.signature)
		}
	case fc.argsAccum.Len() > 0:
		// Partial args were accumulated as string fragments.
		raw = buildFunctionCallRaw(fc.name, json.RawMessage(fc.argsAccum.String()), fc.signature)
	default:
		// Name-only function call with no args.
		raw = buildFunctionCallRaw(fc.name, nil, fc.signature)
	}

	ca.parts = append(ca.parts, candidatePart{fcRaw: raw})
	return fc.name
}

// buildFunctionCallRaw constructs the raw JSON for a function call part,
// preserving the outer thoughtSignature when present.
func buildFunctionCallRaw(name string, args json.RawMessage, signature string) json.RawMessage {
	type fcData struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args,omitempty"`
	}
	type fcWrapper struct {
		FunctionCall     fcData `json:"functionCall"`
		ThoughtSignature string `json:"thoughtSignature,omitempty"`
	}
	w := fcWrapper{FunctionCall: fcData{Name: name, Args: args}, ThoughtSignature: signature}
	raw, err := json.Marshal(w)
	if err != nil {
		return nil
	}
	return raw
}

// parseGeminiStream parses the SSE stream from Gemini APIs and returns
// the aggregated response with usage statistics and tool calls.
//
// SSE framing: Gemini emits one JSON object per "data:" line. We
// intentionally only support this observed single-line framing
// (consistent with the OpenAI SSE parser) rather than the full
// multi-line SSE spec.
//
// Error handling: bare {"error": ...} records on an HTTP 200 stream
// are treated as API errors (consistent with the official Google Gen AI
// Go client behavior).
func parseGeminiStream(reader io.Reader) (*request.GeminiResponse, []request.ToolCall) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	candidates := make(map[int]*candidateAggregator)
	var toolCalls []request.ToolCall
	var modelVersion string
	var responseID string
	var usage *request.GeminiUsage
	var streamError *request.GeminiError

	for scanner.Scan() {
		line := scanner.Text()

		data, ok := extractSSEData(line)
		if !ok {
			// Check for bare error envelope (not wrapped in "data:" prefix).
			if err := tryParseErrorLine(line); err != nil {
				streamError = err
			}
			continue
		}

		var chunk geminiStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			slog.Debug("parseGeminiStream: failed to parse chunk", "error", err)
			continue
		}

		// Check if this data line is itself an error envelope.
		if chunk.Candidates == nil && chunk.UsageMetadata == nil {
			if err := tryParseErrorLine(data); err != nil {
				streamError = err
				continue
			}
		}

		if chunk.ModelVersion != "" {
			modelVersion = chunk.ModelVersion
		}
		if chunk.ResponseID != "" {
			responseID = chunk.ResponseID
		}
		if chunk.UsageMetadata != nil && geminiUsageHasTokens(chunk.UsageMetadata) {
			usage = chunk.UsageMetadata
		}

		for i := range chunk.Candidates {
			c := &chunk.Candidates[i]
			if c.Index < 0 || c.Index >= maxGeminiStreamCandidates {
				continue
			}
			agg := candidates[c.Index]
			if agg == nil {
				agg = &candidateAggregator{}
				candidates[c.Index] = agg
			}

			if c.FinishReason != "" {
				agg.finishReason = c.FinishReason
			}
			if len(c.SafetyRatings) > 0 {
				agg.safetyRatings = c.SafetyRatings
			}
			if c.Content == nil {
				continue
			}

			for _, rawPart := range c.Content.Parts {
				var part geminiStreamPart
				if err := json.Unmarshal(rawPart, &part); err != nil {
					slog.Debug("parseGeminiStream: failed to parse part", "error", err)
					continue
				}

				if part.FunctionCall != nil {
					processFunctionCallPart(agg, part.FunctionCall, part.ThoughtSignature, &toolCalls)
					continue
				}

				// Text part, including signature-only parts (empty text with a
				// thoughtSignature) that must be preserved.
				if part.Text != "" || part.ThoughtSignature != "" {
					// Flush any active function call before appending text.
					if name := agg.flushActiveFC(); name != "" {
						toolCalls = append(toolCalls, request.ToolCall{Name: name})
					}
					appendTextPart(agg, part)
				}
			}
		}
	}

	// Flush any remaining active function calls.
	for _, agg := range candidates {
		if name := agg.flushActiveFC(); name != "" {
			toolCalls = append(toolCalls, request.ToolCall{Name: name})
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Debug("parseGeminiStream: scanner error", "error", err)
	}

	resp := &request.GeminiResponse{
		ModelVersion: modelVersion,
		ResponseID:   responseID,
	}

	if usage != nil {
		resp.UsageMetadata = *usage
	}
	if streamError != nil {
		resp.Error = streamError
	}

	resp.Candidates = buildGeminiCandidates(candidates)

	return resp, toolCalls
}

// appendTextPart adds a text fragment to the candidate aggregator, coalescing
// only with the previous part when both are text parts with equivalent metadata
// (thought flag) and neither carries a thoughtSignature. Signed parts stay
// distinct. Uses strings.Builder for efficient concatenation.
func appendTextPart(agg *candidateAggregator, tp geminiStreamPart) {
	n := len(agg.parts)
	// Coalesce with the previous text part only when metadata matches and
	// neither the previous nor the current part is signed.
	if n > 0 && agg.parts[n-1].textBuilder != nil &&
		agg.parts[n-1].thought == tp.Thought &&
		agg.parts[n-1].signature == "" && tp.ThoughtSignature == "" {
		agg.parts[n-1].textBuilder.WriteString(tp.Text)
		return
	}
	b := &strings.Builder{}
	b.WriteString(tp.Text)
	agg.parts = append(agg.parts, candidatePart{
		textBuilder: b,
		thought:     tp.Thought,
		signature:   tp.ThoughtSignature,
	})
}

// processFunctionCallPart handles a function call part, supporting both
// complete single-chunk calls and Vertex AI's streaming function call
// arguments where the name arrives first and args follow in subsequent chunks.
// signature is the part's outer thoughtSignature (if any).
func processFunctionCallPart(agg *candidateAggregator, fc *geminiFunctionCallData, signature string, toolCalls *[]request.ToolCall) {
	if fc.Name != "" {
		// New named function call: flush any previous active FC.
		if name := agg.flushActiveFC(); name != "" {
			*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
		}

		// If the call has complete args and no continuation, store directly.
		if len(fc.Args) > 0 && len(fc.PartialArgs) == 0 {
			agg.activeFC = &fcAggregator{
				name:       fc.Name,
				signature:  signature,
				hasFullArg: true,
				fullArg:    fc.Args,
			}
			// If willContinue is nil or false, this is a complete call.
			if fc.WillContinue == nil || !*fc.WillContinue {
				if name := agg.flushActiveFC(); name != "" {
					*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
				}
			}
			return
		}

		// Start aggregation (name only, or name with partial args).
		agg.activeFC = &fcAggregator{name: fc.Name, signature: signature}
		agg.activeFC.addPartialArgs(fc.PartialArgs)

		// If no continuation expected and no partial args, flush immediately.
		if fc.WillContinue == nil && len(fc.PartialArgs) == 0 && len(fc.Args) == 0 {
			if name := agg.flushActiveFC(); name != "" {
				*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
			}
		}
		return
	}

	// Continuation fragment (no name): append to active function call.
	if agg.activeFC == nil {
		return
	}
	if len(fc.PartialArgs) > 0 {
		agg.activeFC.addPartialArgs(fc.PartialArgs)
	} else if len(fc.Args) > 0 {
		// Args as JSON in continuation.
		agg.activeFC.argsAccum.Write(fc.Args)
	}

	// If willContinue is explicitly false or absent, the call is complete.
	if fc.WillContinue == nil || !*fc.WillContinue {
		if name := agg.flushActiveFC(); name != "" {
			*toolCalls = append(*toolCalls, request.ToolCall{Name: name})
		}
	}
}

// tryParseErrorLine attempts to parse a line as a bare Gemini error envelope.
// Returns the error if found, nil otherwise.
func tryParseErrorLine(line string) *request.GeminiError {
	line = strings.TrimSpace(line)
	if line == "" || line[0] != '{' {
		return nil
	}
	var envelope geminiStreamError
	if err := json.Unmarshal([]byte(line), &envelope); err != nil {
		return nil
	}
	if envelope.Error != nil && (envelope.Error.Code != 0 || envelope.Error.Status != "" || envelope.Error.Message != "") {
		return envelope.Error
	}
	return nil
}

// extractSSEData extracts the JSON payload from an SSE data line.
// It handles both "data: " (with space) and "data:" (without space) prefixes.
func extractSSEData(line string) (string, bool) {
	if strings.HasPrefix(line, "data: ") {
		return line[6:], true
	}
	if strings.HasPrefix(line, "data:") {
		return line[5:], true
	}
	return "", false
}

// geminiUsageHasTokens returns true when any of the exported token
// fields are populated, not just totalTokenCount.
func geminiUsageHasTokens(u *request.GeminiUsage) bool {
	return u.PromptTokenCount > 0 || u.CandidatesTokenCount > 0 || u.TotalTokenCount > 0
}

// buildGeminiCandidates constructs the final candidate list from the
// per-index aggregators, ordered by candidate index.
func buildGeminiCandidates(aggs map[int]*candidateAggregator) []request.GeminiCandidate {
	if len(aggs) == 0 {
		return nil
	}

	maxIdx := 0
	for idx := range aggs {
		if idx > maxIdx {
			maxIdx = idx
		}
	}

	result := make([]request.GeminiCandidate, maxIdx+1)
	for idx, agg := range aggs {
		parts := buildGeminiStreamParts(agg.parts)
		result[idx] = request.GeminiCandidate{
			Content: &request.GeminiContent{
				Parts: parts,
				Role:  "model",
			},
			FinishReason:  agg.finishReason,
			SafetyRatings: agg.safetyRatings,
		}
	}
	return result
}

// buildGeminiStreamParts constructs the parts JSON from ordered candidate
// parts, preserving the original text/function-call ordering and coalescing
// only adjacent text fragments with equivalent metadata (thought flag).
func buildGeminiStreamParts(parts []candidatePart) json.RawMessage {
	if len(parts) == 0 {
		return nil
	}

	var rawParts []json.RawMessage
	for _, p := range parts {
		if p.fcRaw != nil {
			rawParts = append(rawParts, p.fcRaw)
			continue
		}
		// Emit a text part when it has content or a signature to preserve
		// (signature-only parts must not be dropped).
		if p.textBuilder != nil && (p.textBuilder.Len() > 0 || p.signature != "") {
			raw := marshalTextPart(p.textBuilder.String(), p.thought, p.signature)
			if raw != nil {
				rawParts = append(rawParts, raw)
			}
		}
	}

	if len(rawParts) == 0 {
		return nil
	}

	raw, err := json.Marshal(rawParts)
	if err != nil {
		return nil
	}
	return raw
}

// marshalTextPart marshals a text part, including thought and thoughtSignature
// metadata when present.
func marshalTextPart(text string, thought bool, signature string) json.RawMessage {
	type textPartJSON struct {
		Text             string `json:"text,omitempty"`
		Thought          bool   `json:"thought,omitempty"`
		ThoughtSignature string `json:"thoughtSignature,omitempty"`
	}
	raw, err := json.Marshal(textPartJSON{Text: text, Thought: thought, ThoughtSignature: signature})
	if err != nil {
		return nil
	}
	return raw
}
