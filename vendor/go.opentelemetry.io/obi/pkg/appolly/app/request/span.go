// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	grpc_codes "google.golang.org/grpc/codes"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/common/dnsparser"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

type EventType uint8

// The following consts need to coincide with some C identifiers:
// EVENT_HTTP_REQUEST, EVENT_GRPC_REQUEST, EVENT_HTTP_CLIENT, EVENT_GRPC_CLIENT, EVENT_SQL_CLIENT
const (
	// EventTypeProcessAlive is an internal signal. It will be ignored by the metrics exporters.
	EventTypeProcessAlive EventType = iota
	EventTypeHTTP
	EventTypeGRPC
	EventTypeHTTPClient
	EventTypeGRPCClient
	EventTypeSQLClient
	EventTypeRedisClient
	EventTypeKafkaClient
	EventTypeMQTTClient
	EventTypeRedisServer
	EventTypeKafkaServer
	EventTypeMQTTServer
	EventTypeMongoClient
	EventTypeManualSpan
	EventTypeGPUCudaKernelLaunch
	EventTypeGPUCudaGraphLaunch
	EventTypeGPUCudaMalloc
	EventTypeGPUCudaMemcpy
	EventTypeFailedConnect
	EventTypeDNS
	EventTypeCouchbaseClient
	EventTypeMemcachedClient
	EventTypeMemcachedServer
	EventTypeSQLServer
	EventTypeNATSClient
	EventTypeNATSServer
	EventTypeAMQPClient
	EventTypeSunRPCClient
	EventTypeSunRPCServer
)

const (
	envOTLPProtocol        = "OTEL_EXPORTER_OTLP_PROTOCOL"
	envOTLPTracesProtocol  = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	envOTLPMetricsProtocol = "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"
	envOTLPEndpoint        = "OTEL_EXPORTER_OTLP_ENDPOINT"
	envOTLPTracesEndpoint  = "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"
	envOTLPMetricsEndpoint = "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"
	otlpGrpcProtocol       = "grpc"
)

const (
	metricsDetectPattern     = "/v1/metrics"
	grpcMetricsDetectPattern = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"
	tracesDetectPattern      = "/v1/traces"
	grpcTracesDetectPattern  = "/opentelemetry.proto.collector.trace.v1.TraceService/Export"
)

const (
	SchemeHostSeparator = ";"
)

type SQLKind uint8

const (
	DBGeneric SQLKind = iota + 1
	DBPostgres
	DBMySQL
	DBMSSQL
)

const (
	HTTPSubtypeNone          = 0  // http
	HTTPSubtypeGraphQL       = 1  // http + graphql
	HTTPSubtypeElasticsearch = 2  // http + elasticsearch
	HTTPSubtypeAWSS3         = 3  // http + aws s3
	HTTPSubtypeAWSSQS        = 4  // http + aws sqs
	HTTPSubtypeSQLPP         = 5  // http + sql++ (couchbase, etc.)
	HTTPSubtypeOpenAI        = 6  // http + OpenAI
	HTTPSubtypeAnthropic     = 7  // http + Anthropic
	HTTPSubtypeGemini        = 8  // http + Google AI Studio (Gemini)
	HTTPSubtypeJSONRPC       = 9  // http + JSON-RPC
	HTTPSubtypeAWSBedrock    = 10 // http + AWS Bedrock
	HTTPSubtypeQwen          = 11 // http + Qwen (DashScope)
	HTTPSubtypeMCP           = 12 // http + Model Context Protocol
	HTTPSubtypeEmbedding     = 13 // http + generic embedding provider (Voyage, Cohere, Jina)
	HTTPSubtypeRerank        = 14 // http + Rerank (Cohere, Jina, Voyage, etc.)
	HTTPSubtypeRetrieval     = 15 // http + vector retrieval (Pinecone, Qdrant, Milvus, Chroma, Weaviate, etc.)
)

func IsGenAISubtype(subtype int) bool {
	return subtype == HTTPSubtypeOpenAI ||
		subtype == HTTPSubtypeAnthropic ||
		subtype == HTTPSubtypeGemini ||
		subtype == HTTPSubtypeQwen ||
		subtype == HTTPSubtypeAWSBedrock ||
		subtype == HTTPSubtypeMCP ||
		subtype == HTTPSubtypeEmbedding ||
		subtype == HTTPSubtypeRerank ||
		subtype == HTTPSubtypeRetrieval
}

//nolint:cyclop
func (t EventType) String() string {
	switch t {
	case EventTypeProcessAlive:
		return "ProcessAlive"
	case EventTypeHTTP:
		return "HTTP"
	case EventTypeGRPC:
		return "GRPC"
	case EventTypeHTTPClient:
		return "HTTPClient"
	case EventTypeGRPCClient:
		return "GRPCClient"
	case EventTypeSQLClient:
		return "SQLClient"
	case EventTypeSQLServer:
		return "SQLServer"
	case EventTypeRedisClient:
		return "RedisClient"
	case EventTypeKafkaClient:
		return "KafkaClient"
	case EventTypeMQTTClient:
		return "MQTTClient"
	case EventTypeNATSClient:
		return "NATSClient"
	case EventTypeAMQPClient:
		return "AMQPClient"
	case EventTypeSunRPCClient:
		return "SunRPCClient"
	case EventTypeSunRPCServer:
		return "SunRPCServer"
	case EventTypeRedisServer:
		return "RedisServer"
	case EventTypeKafkaServer:
		return "KafkaServer"
	case EventTypeMQTTServer:
		return "MQTTServer"
	case EventTypeNATSServer:
		return "NATSServer"
	case EventTypeGPUCudaKernelLaunch:
		return "CUDALaunchKernel"
	case EventTypeGPUCudaGraphLaunch:
		return "CUDALaunchGraph"
	case EventTypeGPUCudaMalloc:
		return "CUDAMalloc"
	case EventTypeGPUCudaMemcpy:
		return "CUDAMemcpy"
	case EventTypeMongoClient:
		return "MongoClient"
	case EventTypeManualSpan:
		return "CUSTOM"
	case EventTypeFailedConnect:
		return "CONNECTION ERR"
	case EventTypeDNS:
		return "DNS"
	case EventTypeCouchbaseClient:
		return "CouchbaseClient"
	case EventTypeMemcachedClient:
		return "MemcachedClient"
	case EventTypeMemcachedServer:
		return "MemcachedServer"
	default:
		return fmt.Sprintf("UNKNOWN (%d)", t)
	}
}

func (t EventType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

const (
	MessagingPublish = "publish"
	MessagingProcess = "process"
)

type converter struct {
	clock     func() time.Time
	monoClock func() time.Duration
}

var clocks = converter{monoClock: timing.MonoTimeNow, clock: time.Now}

// PidInfo stores different views of the PID of the process that generated the span
type PidInfo struct {
	// HostPID is the PID as seen by the host (root cgroup)
	HostPID app.PID
	// UserID is the PID as seen by the user space.
	// Might differ from HostPID if the process is in a different namespace/cgroup/container/etc.
	UserPID app.PID
	// Namespace for the PIDs
	Namespace uint32
}

type DBError struct {
	ErrorCode   string
	Description string
}

type SQLError struct {
	Code     uint16 `json:"code"`
	SQLState string `json:"sqlState"`
	Message  string `json:"message"`
}

type MessagingInfo struct {
	Offset    int64 `json:"offset"`
	Partition int   `json:"partition"`
}

type GraphQL struct {
	Document      string `json:"document"`
	OperationName string `json:"operationName"`
	OperationType string `json:"operationType"`
}

type Elasticsearch struct {
	DBCollectionName string `json:"dbCollectionName"`
	NodeName         string `json:"nodeName"`
	DBOperationName  string `json:"dbOperationName"`
	DBQueryText      string `json:"dbQueryText"`
	DBSystemName     string `json:"dbSystemName"`
}

type AWS struct {
	// https://opentelemetry.io/docs/specs/semconv/object-stores/s3/
	S3 AWSS3 `json:"s3"`
	// https://opentelemetry.io/docs/specs/semconv/messaging/sqs/
	SQS AWSSQS `json:"sqs"`
}

type AWSMeta struct {
	RequestID         string `json:"requestId"`
	ExtendedRequestID string `json:"extendedRequestId"`
	Region            string `json:"region"`
}

type AWSS3 struct {
	Meta   AWSMeta `json:"meta"`
	Method string  `json:"method"`
	Bucket string  `json:"bucket"`
	Key    string  `json:"key"`
}

type AWSSQS struct {
	Meta          AWSMeta `json:"meta"`
	OperationName string  `json:"operationName"`
	OperationType string  `json:"operationType"`
	Destination   string  `json:"destination"`
	QueueURL      string  `json:"queueUrl"`
	MessageID     string  `json:"messageId"`
}

type GenAI struct {
	OpenAI    *VendorOpenAI
	Anthropic *VendorAnthropic
	Gemini    *VendorGemini
	// Qwen reuses VendorOpenAI because DashScope's compatible-mode API
	// returns the same JSON structure as OpenAI.  The native generation
	// API uses slightly different field names (request_id, output,
	// input_tokens/output_tokens) but VendorOpenAI already accommodates
	// both via GetInputTokens()/GetOutputTokens() and the Output field.
	// A separate field (rather than sharing OpenAI) keeps provider
	// routing explicit and allows future divergence without refactoring.
	Qwen      *VendorOpenAI
	Bedrock   *VendorBedrock
	MCP       *MCPCall
	Embedding *VendorEmbedding
	Rerank    *VendorRerank
	Retrieval *VendorRetrieval
}

type OpenAIPromptTokensDetails struct {
	CachedTokens        int `json:"cached_tokens,omitempty"`
	CacheCreationTokens int `json:"cache_creation_tokens,omitempty"`
}

type OpenAIUsage struct {
	InputTokens         int                        `json:"input_tokens"`
	OutputTokens        int                        `json:"output_tokens"`
	TotalTokens         int                        `json:"total_tokens"`
	PromptTokens        int                        `json:"prompt_tokens"`
	CompletionTokens    int                        `json:"completion_tokens"`
	CompletionDetails   *OpenAICompletionDetails   `json:"completion_tokens_details,omitempty"`
	PromptTokensDetails *OpenAIPromptTokensDetails `json:"prompt_tokens_details,omitempty"`
}

type OpenAICompletionDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

func (u *OpenAIUsage) GetInputTokens() int {
	if u.InputTokens > 0 {
		return u.InputTokens
	}

	return u.PromptTokens
}

func (u *OpenAIUsage) GetOutputTokens() int {
	if u.OutputTokens > 0 {
		return u.OutputTokens
	}

	if u.CompletionTokens > 0 {
		return u.CompletionTokens
	}

	// Embedding responses only report prompt_tokens and total_tokens.
	// Derive output tokens from the difference.
	if u.TotalTokens > 0 && u.PromptTokens > 0 {
		return u.TotalTokens - u.PromptTokens
	}

	return 0
}

type OpenAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// ToolCall represents a tool invocation requested by an LLM.
type ToolCall struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

type VendorOpenAI struct {
	OperationName     string          `json:"object"`
	ResponseModel     string          `json:"model"`
	Error             OpenAIError     `json:"error"`
	ID                string          `json:"id"`
	FrequencyPenalty  float64         `json:"frequency_penalty"`
	Temperature       float64         `json:"temperature"`
	TopP              float64         `json:"top_p"`
	Usage             OpenAIUsage     `json:"usage"`
	Output            json.RawMessage `json:"output"`
	Request           OpenAIInput
	Choices           json.RawMessage `json:"choices"`
	Items             json.RawMessage `json:"items"`
	Metadata          json.RawMessage `json:"metadata"`
	Data              json.RawMessage `json:"data"`
	ServiceTier       string          `json:"service_tier,omitempty"`
	SystemFingerprint string          `json:"system_fingerprint,omitempty"`
	APIType           string          `json:"-"`
	ToolCalls         []ToolCall      `json:"-"`
}

func (ai *VendorOpenAI) GetFinishReasons() []string {
	if len(ai.Choices) == 0 {
		return nil
	}
	var choices []struct {
		FinishReason string `json:"finish_reason"`
	}
	if err := json.Unmarshal(ai.Choices, &choices); err != nil {
		return nil
	}
	var reasons []string
	for _, c := range choices {
		if c.FinishReason != "" {
			reasons = append(reasons, c.FinishReason)
		}
	}
	return reasons
}

func (ai *VendorOpenAI) GetOutput() string {
	return normalizeOpenAIOutput(ai)
}

func (ai *VendorOpenAI) GetEmbeddingDimensions() int {
	if ai.Request.Dimensions > 0 {
		return ai.Request.Dimensions
	}
	if len(ai.Data) == 0 {
		return 0
	}
	var data []struct {
		Embedding []json.Number `json:"embedding"`
	}
	if err := json.Unmarshal(ai.Data, &data); err != nil || len(data) == 0 {
		return 0
	}
	return len(data[0].Embedding)
}

type OpenAIInput struct {
	Input           string          `json:"input"`
	Prompt          string          `json:"prompt"`
	Model           string          `json:"model"`
	Instructions    string          `json:"instructions"`
	Messages        json.RawMessage `json:"messages"`
	Items           json.RawMessage `json:"items"`
	Temperature     float64         `json:"temperature"`
	Dimensions      int             `json:"dimensions,omitempty"`
	MaxTokens       int             `json:"max_tokens,omitempty"`
	N               int             `json:"n,omitempty"`
	Stop            json.RawMessage `json:"stop,omitempty"`
	PresencePenalty float64         `json:"presence_penalty,omitempty"`
	Stream          bool            `json:"stream,omitempty"`
	EncodingFormat  string          `json:"encoding_format,omitempty"`
	Seed            *int            `json:"seed,omitempty"`
	Tools           json.RawMessage `json:"tools,omitempty"`
	ServiceTier     string          `json:"service_tier,omitempty"`
}

func (air *OpenAIInput) GetStopSequences() []string {
	if len(air.Stop) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(air.Stop, &arr); err == nil {
		return arr
	}
	var s string
	if err := json.Unmarshal(air.Stop, &s); err == nil {
		return []string{s}
	}
	return nil
}

func (air *OpenAIInput) GetInput() string {
	if len(air.Input) > 0 {
		return wrapTextAsInputMessage(air.Input)
	}

	if len(air.Prompt) > 0 {
		return wrapTextAsInputMessage(air.Prompt)
	}

	if len(air.Items) > 0 {
		return string(air.Items)
	}

	return normalizeOpenAIMessages(air.Messages)
}

type VendorAnthropic struct {
	Input     AnthropicRequest
	Output    AnthropicResponse
	ToolCalls []ToolCall `json:"-"`
}

type AnthropicRequest struct {
	MaxTokens     int             `json:"max_tokens"`
	Messages      json.RawMessage `json:"messages"`
	Model         string          `json:"model"`
	Stream        bool            `json:"stream"`
	System        string          `json:"system"`
	Tools         json.RawMessage `json:"tools"`
	Temperature   *float64        `json:"temperature,omitempty"`
	TopP          *float64        `json:"top_p,omitempty"`
	TopK          int             `json:"top_k,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
}

type AnthropicResponse struct {
	Model        string          `json:"model"`
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Role         string          `json:"role"`
	Content      json.RawMessage `json:"content"`
	StopReason   string          `json:"stop_reason"`
	StopSequence *string         `json:"stop_sequence"`
	Usage        AnthropicUsage  `json:"usage"`
	Error        *AnthropicError `json:"error,omitempty"`
	RequestID    string          `json:"request_id"`
}

type AnthropicUsage struct {
	InputTokens              int    `json:"input_tokens"`
	OutputTokens             int    `json:"output_tokens"`
	CacheCreationInputTokens int    `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int    `json:"cache_read_input_tokens,omitempty"`
	ReasoningOutputTokens    int    `json:"reasoning_output_tokens,omitempty"`
	ServiceTier              string `json:"service_tier"`
	InferenceGeo             string `json:"inference_geo"`
}

type AnthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// Google AI Studio (Gemini) types

// DefaultGeminiOperation is the fallback operation name when no operation
// can be extracted from the URL path.
const DefaultGeminiOperation = "generate_content"

type VendorGemini struct {
	Input     GeminiRequest
	Output    GeminiResponse
	Model     string
	Operation string
	IsStream  bool
	ToolCalls []ToolCall `json:"-"`
}

type GeminiRequest struct {
	Contents          json.RawMessage `json:"contents"`
	SystemInstruction *GeminiContent  `json:"systemInstruction,omitempty"`
	Tools             json.RawMessage `json:"tools,omitempty"`
	GenerationConfig  *GeminiGenCfg   `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Parts json.RawMessage `json:"parts"`
	Role  string          `json:"role"`
}

type GeminiGenCfg struct {
	Temperature      float64  `json:"temperature"`
	TopP             float64  `json:"topP"`
	TopK             int      `json:"topK"`
	MaxOutputTokens  int      `json:"maxOutputTokens"`
	FrequencyPenalty float64  `json:"frequencyPenalty"`
	PresencePenalty  float64  `json:"presencePenalty"`
	StopSequences    []string `json:"stopSequences,omitempty"`
	Seed             *int     `json:"seed,omitempty"`
	CandidateCount   int      `json:"candidateCount"`
	ResponseMimeType string   `json:"responseMimeType,omitempty"`
}

type GeminiResponse struct {
	Candidates    []GeminiCandidate `json:"candidates"`
	UsageMetadata GeminiUsage       `json:"usageMetadata"`
	ModelVersion  string            `json:"modelVersion"`
	ResponseID    string            `json:"responseId"`
	Error         *GeminiError      `json:"error,omitempty"`
}

type GeminiCandidate struct {
	Content       *GeminiContent  `json:"content"`
	FinishReason  string          `json:"finishReason"`
	SafetyRatings json.RawMessage `json:"safetyRatings,omitempty"`
}

type GeminiUsage struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

type GeminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

func (g *VendorGemini) GetFinishReasons() []string {
	var reasons []string
	for _, c := range g.Output.Candidates {
		if c.FinishReason != "" {
			reasons = append(reasons, c.FinishReason)
		}
	}
	return reasons
}

// OperationName returns the Gemini API operation name.
// It falls back to DefaultGeminiOperation when no operation was extracted from the URL.
func (g *VendorGemini) OperationName() string {
	if g.Operation != "" {
		return g.Operation
	}
	return DefaultGeminiOperation
}

func (g *VendorGemini) GetOutput() string {
	return normalizeGeminiOutput(&g.Output)
}

func (g *VendorGemini) GetInput() string {
	return normalizeGeminiInput(g.Input.Contents)
}

func (g *VendorGemini) GetSystemInstruction() string {
	if g.Input.SystemInstruction != nil {
		return normalizeGeminiParts(g.Input.SystemInstruction.Parts)
	}
	return ""
}

// AWS Bedrock types
// Bedrock is a multi-model gateway; request/response shape varies by model family.
// We capture the unified superset using omitempty and RawMessage for variable fields.

type VendorBedrock struct {
	Input       BedrockRequest
	Output      BedrockResponse
	Model       string // extracted from URL path: /model/{modelId}/invoke
	IsStream    bool
	GuardrailID string
}

// BedrockRequest covers the common fields across all model families.
// The messages/prompt/inputText fields differ per model family,
// so we capture them as raw JSON where needed.
type BedrockRequest struct {
	// Anthropic Claude / Amazon Nova format
	Messages    json.RawMessage `json:"messages,omitempty"`
	System      string          `json:"system,omitempty"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
	TopP        float64         `json:"top_p,omitempty"`
	TopK        int             `json:"top_k,omitempty"`
	// Amazon Titan format
	InputText            string          `json:"inputText,omitempty"`
	TextGenerationConfig *TitanGenConfig `json:"textGenerationConfig,omitempty"`
	// Meta Llama format
	Prompt    string `json:"prompt,omitempty"`
	MaxGenLen int    `json:"max_gen_len,omitempty"`
	// Tool use (Claude / Nova)
	Tools         json.RawMessage `json:"tools,omitempty"`
	StopSequences []string        `json:"stop_sequences,omitempty"`
}

type TitanGenConfig struct {
	MaxTokenCount int     `json:"maxTokenCount,omitempty"`
	Temperature   float64 `json:"temperature,omitempty"`
	TopP          float64 `json:"topP,omitempty"`
}

// BedrockResponse covers the common response fields across all model families.
// Token counts are read from response headers (more reliable than body) and stored here.
type BedrockResponse struct {
	// Anthropic Claude format
	Content    json.RawMessage `json:"content,omitempty"`
	StopReason string          `json:"stop_reason,omitempty"`
	Usage      *BedrockUsage   `json:"usage,omitempty"`
	// Amazon Nova format
	Output         *NovaOutput `json:"output,omitempty"`
	StopReasonNova string      `json:"stopReason,omitempty"`
	// Meta Llama format
	Generation           string `json:"generation,omitempty"`
	PromptTokenCount     int    `json:"prompt_token_count,omitempty"`
	GenerationTokenCount int    `json:"generation_token_count,omitempty"`
	// Amazon Titan format
	Results []TitanResult `json:"results,omitempty"`
	// Error fields appear at the top level of the Bedrock error response body
	ErrorType    string `json:"__type,omitempty"`
	ErrorMessage string `json:"message,omitempty"`
	// Token counts extracted from response headers (not JSON-unmarshalled, set programmatically)
	InputTokens  int `json:"-"`
	OutputTokens int `json:"-"`
}

type BedrockUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type NovaOutput struct {
	Message *NovaMessage `json:"message,omitempty"`
}

type NovaMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content,omitempty"`
}

type TitanResult struct {
	OutputText       string `json:"outputText"`
	CompletionReason string `json:"completionReason,omitempty"`
}

func (b *VendorBedrock) GetInput() string {
	if len(b.Input.Messages) > 0 {
		return NormalizeAnthropicInput(b.Input.Messages)
	}
	if b.Input.Prompt != "" {
		return wrapTextAsInputMessage(b.Input.Prompt)
	}
	if b.Input.InputText != "" {
		return wrapTextAsInputMessage(b.Input.InputText)
	}
	return ""
}

func (b *VendorBedrock) GetOutput() string {
	// Anthropic Claude: content array (normalized via NormalizeBedrockOutput in tracesgen)
	if len(b.Output.Content) > 0 {
		return string(b.Output.Content)
	}
	// Amazon Nova: output.message.content
	if b.Output.Output != nil && b.Output.Output.Message != nil && len(b.Output.Output.Message.Content) > 0 {
		return wrapTextAsOutputMessage(
			b.Output.Output.Message.Role,
			string(b.Output.Output.Message.Content),
			b.Output.StopReasonNova,
		)
	}
	// Meta Llama: generation
	if b.Output.Generation != "" {
		return wrapTextAsOutputMessage("assistant", b.Output.Generation, b.GetStopReason())
	}
	// Amazon Titan: results[0].outputText
	if len(b.Output.Results) > 0 {
		return wrapTextAsOutputMessage("assistant", b.Output.Results[0].OutputText, b.Output.Results[0].CompletionReason)
	}
	return ""
}

func (b *VendorBedrock) GetSystemInstruction() string {
	return NormalizeSystemInstructions(b.Input.System)
}

func (b *VendorBedrock) GetStopReason() string {
	if b.Output.StopReason != "" {
		return b.Output.StopReason
	}
	if b.Output.StopReasonNova != "" {
		return b.Output.StopReasonNova
	}
	return ""
}

// MCPCall holds parsed data from a Model Context Protocol request/response.
type MCPCall struct {
	Method            string `json:"method"`
	ToolName          string `json:"toolName,omitempty"`
	ToolType          string `json:"toolType,omitempty"`
	ToolCallArguments string `json:"toolCallArguments,omitempty"`
	ToolCallResult    string `json:"toolCallResult,omitempty"`
	ResourceURI       string `json:"resourceUri,omitempty"`
	PromptName        string `json:"promptName,omitempty"`
	SessionID         string `json:"sessionId,omitempty"`
	ProtocolVer       string `json:"protocolVer,omitempty"`
	RequestID         string `json:"requestId,omitempty"`
	ErrorCode         int    `json:"errorCode,omitempty"`
	ErrorMessage      string `json:"errorMessage,omitempty"`
}

// OperationName returns the GenAI operation name for the MCP method.
// tools/call maps to execute_tool; other methods return the method name as-is.
func (m *MCPCall) OperationName() string {
	if m.Method == "tools/call" {
		return "execute_tool"
	}
	return m.Method
}

type JSONRPC struct {
	Method       string `json:"method"`
	Version      string `json:"version"`
	RequestID    string `json:"requestId"`
	ErrorCode    int    `json:"errorCode,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
}

// Generic embedding provider types (Voyage AI, Cohere, Jina AI)

// GenAI operation name constants aligned with OTel semantic conventions.
const (
	ChatOperationName        = "chat"
	CompletionOperationName  = "text_completion"
	GenerationOperationName  = "generation"
	InvokeModelOperationName = "invoke_model"
	EmbeddingOperationName   = "embeddings"
)

// VendorEmbedding represents a generic embedding API provider such as
// Voyage AI, Cohere, or Jina AI.
type VendorEmbedding struct {
	Provider string
	Model    string
	Input    EmbeddingRequest
	Output   EmbeddingResponse
}

// OperationName returns the canonical embedding operation name.
func (e *VendorEmbedding) OperationName() string {
	return EmbeddingOperationName
}

// EmbeddingRequest captures the common fields from embedding API requests.
type EmbeddingRequest struct {
	Model      string          `json:"model"`
	Input      json.RawMessage `json:"input"`
	Dimensions int             `json:"dimensions,omitempty"`
	// Cohere uses "texts" instead of "input"
	Texts json.RawMessage `json:"texts,omitempty"`
}

// InputCount returns the number of input texts in the request.
// It handles both single-string and array-of-strings formats.
func (r *EmbeddingRequest) InputCount() int {
	raw := r.Input
	if len(raw) == 0 {
		raw = r.Texts
	}
	if len(raw) == 0 {
		return 0
	}
	// Array of strings: count elements
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		return len(arr)
	}
	// Single string
	return 1
}

// EmbeddingResponse captures the common fields from embedding API responses.
type EmbeddingResponse struct {
	Model string         `json:"model"`
	Usage EmbeddingUsage `json:"usage"`
	// Cohere uses meta.billed_units for token counts
	Meta *CohereResponseMeta `json:"meta,omitempty"`
}

// EmbeddingUsage captures token usage in embedding responses.
type EmbeddingUsage struct {
	PromptTokens int `json:"prompt_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

// CohereResponseMeta captures Cohere-specific response metadata.
type CohereResponseMeta struct {
	BilledUnits *CohereBilledUnits `json:"billed_units,omitempty"`
}

// CohereBilledUnits captures Cohere token billing information.
type CohereBilledUnits struct {
	InputTokens int `json:"input_tokens"`
}

// GetInputTokens returns the input token count, handling provider-specific formats.
func (e *VendorEmbedding) GetInputTokens() int {
	if e.Output.Usage.PromptTokens > 0 {
		return e.Output.Usage.PromptTokens
	}
	if e.Output.Usage.TotalTokens > 0 {
		return e.Output.Usage.TotalTokens
	}
	if e.Output.Meta != nil && e.Output.Meta.BilledUnits != nil {
		return e.Output.Meta.BilledUnits.InputTokens
	}
	return 0
}

// GetOutputTokens returns the output token count for embedding requests,
// derived as total_tokens - prompt_tokens.
func (e *VendorEmbedding) GetOutputTokens() int {
	if e.Output.Usage.TotalTokens > 0 && e.Output.Usage.PromptTokens > 0 {
		return e.Output.Usage.TotalTokens - e.Output.Usage.PromptTokens
	}
	return 0
}

// VendorRerank holds parsed data from a rerank API request/response.
// Reranking services (Cohere, Jina AI, Voyage AI, etc.) share a similar
// REST API shape: POST /v1/rerank with a JSON body containing model,
// query, and documents.  The provider is identified from the request
// hostname.
type VendorRerank struct {
	Input    RerankRequest
	Output   RerankResponse
	Provider string
}

type RerankRequest struct {
	Model     string          `json:"model"`
	Query     string          `json:"query"`
	TopN      int             `json:"top_n"`
	Documents json.RawMessage `json:"documents"`
	// Some providers nest query/documents under "input" and top_n under "parameters".
	NestedInput *struct {
		Query     string          `json:"query"`
		Documents json.RawMessage `json:"documents"`
	} `json:"input,omitempty"`
	NestedParams *struct {
		TopN int `json:"top_n"`
	} `json:"parameters,omitempty"`
}

func (r *RerankRequest) GetQuery() string {
	if r.Query != "" {
		return r.Query
	}
	if r.NestedInput != nil {
		return r.NestedInput.Query
	}
	return ""
}

func (r *RerankRequest) GetDocuments() json.RawMessage {
	if len(r.Documents) > 0 {
		return r.Documents
	}
	if r.NestedInput != nil {
		return r.NestedInput.Documents
	}
	return nil
}

func (r *RerankRequest) GetTopN() int {
	if r.TopN > 0 {
		return r.TopN
	}
	if r.NestedParams != nil && r.NestedParams.TopN > 0 {
		return r.NestedParams.TopN
	}
	return 0
}

type RerankResponse struct {
	ID      string          `json:"id"`
	Model   string          `json:"model"`
	Results json.RawMessage `json:"results"`
	Usage   RerankUsage     `json:"usage"`
	Meta    *RerankMeta     `json:"meta,omitempty"`
	Error   *RerankError    `json:"error,omitempty"`
	// Some providers nest results under "output".
	NestedOutput *struct {
		Results json.RawMessage `json:"results"`
	} `json:"output,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func (r *RerankResponse) GetResults() json.RawMessage {
	if len(r.Results) > 0 {
		return r.Results
	}
	if r.NestedOutput != nil {
		return r.NestedOutput.Results
	}
	return nil
}

func (r *RerankResponse) GetID() string {
	if r.ID != "" {
		return r.ID
	}
	return r.RequestID
}

// RerankMeta represents Cohere-style metadata in the rerank response.
type RerankMeta struct {
	BilledUnits *RerankBilledUnits `json:"billed_units,omitempty"`
	Tokens      *RerankMetaTokens  `json:"tokens,omitempty"`
}

type RerankBilledUnits struct {
	SearchUnits float64 `json:"search_units"`
}

type RerankMetaTokens struct {
	InputTokens int `json:"input_tokens"`
}

type RerankUsage struct {
	TotalTokens  int `json:"total_tokens"`
	PromptTokens int `json:"prompt_tokens"`
	SearchUnits  int `json:"search_units"`
}

func (u *RerankUsage) GetInputTokens() int {
	if u.PromptTokens > 0 {
		return u.PromptTokens
	}
	return u.TotalTokens
}

// GetTotalTokens returns the total token count from any supported response
// format.  It checks usage.total_tokens (Jina/Voyage), then
// usage.prompt_tokens, and finally falls back to meta.tokens.input_tokens
// (Cohere).
func (r *RerankResponse) GetTotalTokens() int {
	if r.Usage.TotalTokens > 0 {
		return r.Usage.TotalTokens
	}
	if r.Usage.PromptTokens > 0 {
		return r.Usage.PromptTokens
	}
	if r.Meta != nil && r.Meta.Tokens != nil && r.Meta.Tokens.InputTokens > 0 {
		return r.Meta.Tokens.InputTokens
	}
	return 0
}

type RerankError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// GetInput returns a JSON representation of the rerank input (query + documents).
func (v *VendorRerank) GetInput() string {
	query := v.Input.GetQuery()
	docs := v.Input.GetDocuments()
	if query == "" && len(docs) == 0 {
		return ""
	}
	obj := struct {
		Query     string          `json:"query,omitempty"`
		Documents json.RawMessage `json:"documents,omitempty"`
	}{
		Query:     query,
		Documents: docs,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(b)
}

// GetOutput returns a JSON representation of the rerank output (results).
func (v *VendorRerank) GetOutput() string {
	results := v.Output.GetResults()
	if len(results) == 0 {
		return ""
	}
	return string(results)
}

// Vector retrieval provider types (Pinecone, Qdrant, Milvus, Chroma, Weaviate, etc.)

// RetrievalOperationName is the canonical operation name for vector
// retrieval spans, aligned with the OpenTelemetry GenAI semantic
// conventions (gen_ai.operation.name = "retrieval").
const RetrievalOperationName = "retrieval"

// VendorRetrieval holds parsed data from a vector database retrieval
// (similarity search) request/response. Vector stores differ significantly
// in their request/response shape, so both Input and Output keep only the
// fields that are common or easy to recover across providers.
type VendorRetrieval struct {
	Provider string
	Input    RetrievalRequest
	Output   RetrievalResponse
}

// OperationName returns the canonical retrieval operation name.
func (r *VendorRetrieval) OperationName() string {
	return RetrievalOperationName
}

// GetCollection returns the collection / index / namespace name, checking
// the provider-specific aliases in order.
func (r *VendorRetrieval) GetCollection() string {
	if r.Input.Collection != "" {
		return r.Input.Collection
	}
	if r.Input.CollectionName != "" {
		return r.Input.CollectionName
	}
	if r.Input.CollectionSnake != "" {
		return r.Input.CollectionSnake
	}
	return r.Input.Namespace
}

// RetrievalRequest captures the common fields from vector search request
// bodies across Pinecone, Qdrant, Milvus, Chroma and Weaviate. Unknown
// fields are ignored; missing fields are harmless.
type RetrievalRequest struct {
	// Model is the embedding model used, when reported by the request body
	// (rarely present; most vector stores do not require a model).
	Model string `json:"model,omitempty"`
	// Collection / index name when the provider places it in the body
	// (Pinecone uses namespace, Milvus uses collectionName, Chroma uses collection).
	Collection      string `json:"collection,omitempty"`
	CollectionName  string `json:"collectionName,omitempty"`
	CollectionSnake string `json:"collection_name,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	// TopK / limit for similarity search results.
	// Pinecone/Qdrant use "topK"/"top_k", Milvus/Chroma use "limit".
	TopK      int `json:"topK,omitempty"`
	TopKSnake int `json:"top_k,omitempty"`
	Limit     int `json:"limit,omitempty"`
}

// GetTopK returns the top-k value from whichever field was populated.
func (r *RetrievalRequest) GetTopK() int {
	if r.TopK > 0 {
		return r.TopK
	}
	if r.TopKSnake > 0 {
		return r.TopKSnake
	}
	return r.Limit
}

// RetrievalResponse captures the common fields from vector search response
// bodies.
type RetrievalResponse struct {
	ID    string         `json:"id,omitempty"`
	Model string         `json:"model,omitempty"`
	Usage RetrievalUsage `json:"usage,omitempty"`
}

// RetrievalUsage captures optional token usage information returned by
// embedding-aware vector stores.
type RetrievalUsage struct {
	TotalTokens  int `json:"total_tokens,omitempty"`
	PromptTokens int `json:"prompt_tokens,omitempty"`
}

type SpanLink struct {
	TraceID    trace.TraceID `json:"traceID"`
	SpanID     trace.SpanID  `json:"spanID"`
	TraceFlags uint8         `json:"traceFlags,string"`
}

// GetInputTokens returns the input token count, preferring prompt_tokens
// and falling back to total_tokens. Returns zero when not reported.
func (r *VendorRetrieval) GetInputTokens() int {
	if r.Output.Usage.PromptTokens > 0 {
		return r.Output.Usage.PromptTokens
	}
	return r.Output.Usage.TotalTokens
}

// Span contains the information being submitted by the following nodes in the graph.
// It enables comfortable handling of data from Go.
// REMINDER: any attribute here must be also added to the functions SpanOTELGetters
// and SpanPromGetters in pkg/appolly/app/request/span_getters_providers.go and
// getDefinitions in pkg/export/attributes/attr_defs.go
type Span struct {
	Type              EventType      `json:"type"`
	Flags             uint8          `json:"-"`
	Method            string         `json:"-"`
	Path              string         `json:"-"`
	FullPath          string         `json:"-"`
	Route             string         `json:"-"`
	Peer              string         `json:"peer"`
	PeerPort          int            `json:"peerPort,string"`
	Host              string         `json:"host"`
	HostPort          int            `json:"hostPort,string"`
	Status            int            `json:"-"`
	ResponseLength    int64          `json:"-"`
	ContentLength     int64          `json:"-"`
	RequestStart      int64          `json:"-"`
	Start             int64          `json:"-"`
	End               int64          `json:"-"`
	Service           svc.Attrs      `json:"-"`
	TraceID           trace.TraceID  `json:"traceID"`
	SpanID            trace.SpanID   `json:"spanID"`
	ParentSpanID      trace.SpanID   `json:"parentSpanID"`
	TraceFlags        uint8          `json:"traceFlags,string"`
	Links             []SpanLink     `json:"links,omitempty"`
	Pid               PidInfo        `json:"-"`
	PeerName          string         `json:"peerName"`
	HostName          string         `json:"hostName"`
	OtherNamespace    string         `json:"-"`
	OtherK8SNamespace string         `json:"-"`
	Statement         string         `json:"-"`
	SubType           int            `json:"-"`
	DBError           DBError        `json:"-"`
	DBNamespace       string         `json:"-"`
	DBSystem          string         `json:"-"`
	SQLCommand        string         `json:"-"`
	SQLError          *SQLError      `json:"-"`
	MessagingInfo     *MessagingInfo `json:"-"`
	GraphQL           *GraphQL       `json:"-"`
	Elasticsearch     *Elasticsearch `json:"-"`
	AWS               *AWS           `json:"-"`
	GenAI             *GenAI         `json:"-"`
	JSONRPC           *JSONRPC       `json:"-"`

	// RequestHeaders stores extracted HTTP request headers based on enrichment rules.
	// Keys are canonical header names, values are all header values (possibly obfuscated).
	RequestHeaders map[string][]string `json:"requestHeaders,omitempty"`
	// ResponseHeaders stores extracted HTTP response headers based on enrichment rules.
	ResponseHeaders map[string][]string `json:"responseHeaders,omitempty"`

	// RequestBodyContent stores the extracted HTTP request body (JSON string, possibly with obfuscated fields).
	RequestBodyContent string `json:"requestBodyContent,omitempty"`
	// ResponseBodyContent stores the extracted HTTP response body (JSON string, possibly with obfuscated fields).
	ResponseBodyContent string `json:"responseBodyContent,omitempty"`

	// OverrideTraceName is set under some conditions, like spanmetrics reaching the maximum
	// cardinality for trace names.
	OverrideTraceName string `json:"-"`
}

func (s *Span) Inside(parent *Span) bool {
	return s.RequestStart >= parent.RequestStart && s.End <= parent.End
}

// InternalSignal returns whether a span is not aimed to be exported as a metric
// or a trace, because it's used to internally send messages through the pipeline.
func (s *Span) InternalSignal() bool {
	return s.Type == EventTypeProcessAlive
}

// helper attribute functions used by JSON serialization
type SpanAttributes map[string]string

func spanAttributes(s *Span) SpanAttributes {
	switch s.Type {
	case EventTypeHTTP:
		attrs := SpanAttributes{
			"method":      s.Method,
			"status":      strconv.Itoa(s.Status),
			"url":         s.Path,
			"contentLen":  strconv.FormatInt(s.ContentLength, 10),
			"responseLen": strconv.FormatInt(s.ResponseLength, 10),
			"route":       s.Route,
			"clientAddr":  SpanPeer(s),
			"serverAddr":  SpanHost(s),
			"serverPort":  strconv.Itoa(s.HostPort),
		}
		if s.SubType == HTTPSubtypeGraphQL && s.GraphQL != nil {
			attrs["graphqlOperationName"] = s.GraphQL.OperationName
			attrs["graphqlOperationType"] = s.GraphQL.OperationType
		}
		if s.SubType == HTTPSubtypeJSONRPC && s.JSONRPC != nil {
			attrs["jsonrpcMethod"] = s.JSONRPC.Method
			attrs["jsonrpcVersion"] = s.JSONRPC.Version
			attrs["jsonrpcRequestId"] = s.JSONRPC.RequestID
			attrs["jsonrpcErrorCode"] = strconv.Itoa(s.JSONRPC.ErrorCode)
			if s.JSONRPC.ErrorMessage != "" {
				attrs["jsonrpcErrorMessage"] = s.JSONRPC.ErrorMessage
			}
		}

		addHeaderAttributes(attrs, s)
		return attrs
	case EventTypeHTTPClient:
		attrs := SpanAttributes{
			"method":     s.Method,
			"status":     strconv.Itoa(s.Status),
			"url":        s.Path,
			"clientAddr": SpanPeer(s),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
		if s.SubType == HTTPSubtypeElasticsearch && s.Elasticsearch != nil {
			attrs["dbCollectionName"] = s.Elasticsearch.DBCollectionName
			attrs["nodeName"] = s.Elasticsearch.NodeName
			attrs["dbOperationName"] = s.Elasticsearch.DBOperationName
			attrs["dbQueryText"] = s.Elasticsearch.DBQueryText
			attrs["dbSystemName"] = s.Elasticsearch.DBSystemName
		}
		if s.SubType == HTTPSubtypeAWSS3 && s.AWS != nil {
			s3 := s.AWS.S3
			attrs["awsRequestID"] = s3.Meta.RequestID
			attrs["awsExtendedRequestID"] = s3.Meta.ExtendedRequestID
			attrs["awsRegion"] = s3.Meta.Region
			attrs["awsS3Method"] = s3.Method
			attrs["awsS3Bucket"] = s3.Bucket
			attrs["awsS3Key"] = s3.Key
		}
		if s.SubType == HTTPSubtypeAWSSQS && s.AWS != nil {
			sqs := s.AWS.SQS
			attrs["awsRequestID"] = sqs.Meta.RequestID
			attrs["awsExtendedRequestID"] = sqs.Meta.ExtendedRequestID
			attrs["awsRegion"] = sqs.Meta.Region
			attrs["awsSQSOperationName"] = sqs.OperationName
			attrs["awsSQSOperationType"] = sqs.OperationType
			attrs["awsSQSDestination"] = sqs.Destination
			attrs["awsSQSQueueURL"] = sqs.QueueURL
			attrs["awsSQSMessageID"] = sqs.MessageID
		}
		if s.SubType == HTTPSubtypeSQLPP {
			attrs["dbCollectionName"] = s.Route
			attrs["dbOperationName"] = s.Method
			attrs["dbQueryText"] = s.Statement
			attrs["dbSystemName"] = s.DBSystem
			attrs["dbNamespace"] = s.DBNamespace
			if s.DBError.ErrorCode != "" {
				attrs["errorType"] = s.DBError.ErrorCode
				attrs["errorDescription"] = s.DBError.Description
			}
		}
		addHeaderAttributes(attrs, s)
		return attrs
	case EventTypeGRPC:
		return SpanAttributes{
			"method":     s.Path,
			"status":     strconv.Itoa(s.Status),
			"clientAddr": SpanPeer(s),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
	case EventTypeGRPCClient:
		return SpanAttributes{
			"method":     s.Path,
			"status":     strconv.Itoa(s.Status),
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
		}
	case EventTypeSQLClient, EventTypeSQLServer:
		var (
			code              uint16
			sqlState, message string
		)

		if s.SQLError != nil {
			code = s.SQLError.Code
			sqlState = s.SQLError.SQLState
			message = s.SQLError.Message
		}

		return SpanAttributes{
			"serverAddr":       SpanHost(s),
			"serverPort":       strconv.Itoa(s.HostPort),
			"operation":        s.Method,
			"table":            s.Path,
			"statement":        s.Statement,
			"sqlCommand":       s.SQLCommand,
			"errorCode":        strconv.FormatUint(uint64(code), 10),
			"sqlState":         sqlState,
			"errorMessage":     message,
			"errorDescription": s.SQLErrorDescription(),
		}
	case EventTypeRedisServer:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"statement":  s.Statement,
			"query":      s.Path,
		}
	case EventTypeKafkaServer, EventTypeKafkaClient, EventTypeMQTTServer, EventTypeMQTTClient, EventTypeAMQPClient:
		attrs := SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"clientId":   s.Statement,
			"topic":      s.Path,
		}
		if s.MessagingInfo != nil {
			attrs["partition"] = strconv.FormatUint(uint64(s.MessagingInfo.Partition), 10)
			if s.Method == MessagingProcess {
				attrs["offset"] = strconv.FormatUint(uint64(s.MessagingInfo.Offset), 10)
			}
		}
		return attrs
	case EventTypeNATSServer, EventTypeNATSClient:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"clientId":   s.Statement,
			"subject":    s.Path,
		}
	case EventTypeSunRPCServer, EventTypeSunRPCClient:
		attrs := SpanAttributes{
			"serverAddr":                  SpanHost(s),
			"serverPort":                  strconv.Itoa(s.HostPort),
			attr.OncRPCProgramName.Prom(): s.Path,
			attr.OncRPCVersion.Prom():     strconv.Itoa(s.SubType),
			attr.OncRPCAuthFlavor.Prom():  s.Statement,
			"status":                      strconv.Itoa(s.Status),
		}
		if procRoute := s.SunRPCProcedureRouteForExport(); procRoute != "" {
			attrs[attr.OncRPCProcedureNumber.Prom()] = procRoute
		}
		if procName := s.SunRPCProcedureNameForExport(); procName != "" {
			attrs[attr.OncRPCProcedureName.Prom()] = procName
		}
		return attrs
	case EventTypeGPUCudaKernelLaunch:
		return SpanAttributes{
			"gridSize":  strconv.FormatInt(s.ContentLength, 10),
			"blockSize": strconv.Itoa(s.SubType),
		}
	case EventTypeGPUCudaMalloc:
		return SpanAttributes{
			"size": strconv.FormatInt(s.ContentLength, 10),
		}
	case EventTypeGPUCudaMemcpy:
		return SpanAttributes{
			"size": strconv.FormatInt(s.ContentLength, 10),
			"kind": CudaMemcpyName(s.SubType),
		}
	case EventTypeMongoClient:
		return SpanAttributes{
			"serverAddr": SpanHost(s),
			"serverPort": strconv.Itoa(s.HostPort),
			"operation":  s.Method,
			"table":      s.Path,
		}
	}

	return SpanAttributes{}
}

func addHeaderAttributes(attrs SpanAttributes, s *Span) {
	for name, values := range s.RequestHeaders {
		attrs[attr.HTTPRequestHeaderKey(name)] = strings.Join(values, ", ")
	}
	for name, values := range s.ResponseHeaders {
		attrs[attr.HTTPResponseHeaderKey(name)] = strings.Join(values, ", ")
	}
}

func (s *Span) SQLErrorDescription() string {
	if s.SQLError == nil {
		return ""
	}

	var codeString string
	if s.SQLError.Code == 0 {
		codeString = "NA"
	} else {
		codeString = strconv.FormatUint(uint64(s.SQLError.Code), 10)
	}

	if s.SQLCommand == "" {
		return fmt.Sprintf(
			"SQL Server errored: error_code=%s sql_state=%s message=%s",
			codeString, s.SQLError.SQLState, s.SQLError.Message,
		)
	}

	return fmt.Sprintf(
		"SQL Server errored for command 'COM_%s': error_code=%s sql_state=%s message=%s",
		s.SQLCommand, codeString, s.SQLError.SQLState, s.SQLError.Message,
	)
}

func (s Span) MarshalJSON() ([]byte, error) {
	type JSONSpan Span

	t := s.Timings()
	start := t.RequestStart.UnixMicro()
	handlerStart := t.Start.UnixMicro()
	end := t.End.UnixMicro()
	duration := t.End.Sub(t.RequestStart)
	handlerDuration := t.End.Sub(t.Start)

	aux := struct {
		JSONSpan
		Kind              string         `json:"kind"`
		Start             int64          `json:"start,string"`
		HandlerStart      int64          `json:"handlerStart,string"`
		End               int64          `json:"end,string"`
		Duration          string         `json:"duration"`
		DurationUS        int64          `json:"durationUSec,string"`
		HandlerDuration   string         `json:"handlerDuration"`
		HandlerDurationUS int64          `json:"handlerDurationUSec,string"`
		Attributes        SpanAttributes `json:"attributes"`
	}{
		JSONSpan:          JSONSpan(s),
		Kind:              s.ServiceGraphKind(),
		Start:             start,
		HandlerStart:      handlerStart,
		End:               end,
		Duration:          duration.String(),
		DurationUS:        duration.Microseconds(),
		HandlerDuration:   handlerDuration.String(),
		HandlerDurationUS: handlerDuration.Microseconds(),
		Attributes:        spanAttributes(&s),
	}

	return json.Marshal(aux)
}

type Timings struct {
	RequestStart time.Time
	Start        time.Time
	End          time.Time
}

func (s *Span) Timings() Timings {
	now := clocks.clock()
	monoNow := clocks.monoClock()
	startDelta := monoNow - time.Duration(s.Start)
	endDelta := monoNow - time.Duration(s.End)
	goStartDelta := monoNow - time.Duration(s.RequestStart)

	return Timings{
		RequestStart: now.Add(-goStartDelta),
		Start:        now.Add(-startDelta),
		End:          now.Add(-endDelta),
	}
}

func (s *Span) IsValid() bool {
	if (len(s.Method) > 0 && !utf8.ValidString(s.Method)) ||
		(len(s.Path) > 0 && !utf8.ValidString(s.Path)) {
		return false
	}

	if s.End < s.Start {
		return false
	}

	return true
}

func (s *Span) IsClientSpan() bool {
	switch s.Type {
	case EventTypeGRPCClient, EventTypeDNS, EventTypeHTTPClient, EventTypeRedisClient, EventTypeKafkaClient, EventTypeMQTTClient, EventTypeNATSClient, EventTypeAMQPClient, EventTypeSunRPCClient, EventTypeSQLClient, EventTypeMongoClient, EventTypeFailedConnect, EventTypeCouchbaseClient, EventTypeMemcachedClient:
		return true
	}

	return false
}

func (s *Span) IsHTTPSpan() bool {
	return s.Type == EventTypeHTTP || s.Type == EventTypeHTTPClient
}

const (
	StatusCodeUnset = "STATUS_CODE_UNSET"
	StatusCodeError = "STATUS_CODE_ERROR"
	StatusCodeOk    = "STATUS_CODE_OK"
)

func SpanStatusCode(span *Span) string {
	switch span.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		return HTTPSpanStatusCode(span)
	case EventTypeGRPC, EventTypeGRPCClient:
		return GrpcSpanStatusCode(span)
	case EventTypeSQLClient, EventTypeSQLServer, EventTypeRedisClient, EventTypeRedisServer, EventTypeMongoClient, EventTypeDNS, EventTypeCouchbaseClient, EventTypeMemcachedClient, EventTypeMemcachedServer, EventTypeSunRPCClient, EventTypeSunRPCServer:
		if span.Status != 0 {
			return StatusCodeError
		}
		return StatusCodeUnset
	case EventTypeManualSpan:
		switch span.Status {
		case int(codes.Error):
			return StatusCodeError
		case int(codes.Ok):
			return StatusCodeOk
		}
		return StatusCodeUnset
	case EventTypeFailedConnect:
		return StatusCodeError
	}
	return StatusCodeUnset
}

func SpanDBStatusMessage(span *Span, dbError string) string {
	if span.Status != 0 && dbError != "" {
		return dbError
	}
	return ""
}

func (s *Span) IsDBSpan() bool {
	switch s.Type {
	case EventTypeRedisClient, EventTypeRedisServer, EventTypeMongoClient, EventTypeCouchbaseClient, EventTypeMemcachedClient, EventTypeMemcachedServer, EventTypeSQLClient, EventTypeSQLServer:
		return true
	case EventTypeHTTPClient:
		if s.SubType == HTTPSubtypeSQLPP {
			return true
		}
	}

	return false
}

func SpanStatusMessage(span *Span) string {
	switch span.Type {
	case EventTypeManualSpan:
		return span.Path
	case EventTypeHTTPClient, EventTypeHTTP:
		if span.SubType == HTTPSubtypeJSONRPC && span.JSONRPC != nil && span.JSONRPC.ErrorMessage != "" {
			return span.JSONRPC.ErrorMessage
		}
		if span.SubType == HTTPSubtypeMCP && span.GenAI != nil && span.GenAI.MCP != nil && span.GenAI.MCP.ErrorMessage != "" {
			return span.GenAI.MCP.ErrorMessage
		}
	case EventTypeDNS:
		if span.Status != 0 {
			return dnsparser.RCode(span.Status).String()
		}
	}
	return ""
}

// HTTPSpanStatusCode https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/http/#status
func HTTPSpanStatusCode(span *Span) string {
	if span.Status == 0 {
		return StatusCodeError
	}

	// JSON-RPC errors are signaled in the response body, not via HTTP status code.
	if span.SubType == HTTPSubtypeJSONRPC && span.JSONRPC != nil && span.JSONRPC.ErrorCode != 0 {
		return StatusCodeError
	}

	// MCP errors are signaled in the JSON-RPC response body.
	if span.SubType == HTTPSubtypeMCP && span.GenAI != nil && span.GenAI.MCP != nil && span.GenAI.MCP.ErrorCode != 0 {
		return StatusCodeError
	}

	if span.Type == EventTypeHTTPClient {
		if span.Status < 400 {
			// this is possibly not needed, because in my experiments they
			// respond with 429, but just to be correct according to the OTel
			// GenAI spec: https://opentelemetry.io/docs/specs/semconv/gen-ai/openai/
			if span.GenAI != nil {
				if span.GenAI.OpenAI != nil && span.GenAI.OpenAI.Error.Type != "" {
					return StatusCodeError
				}
				if span.GenAI.Anthropic != nil && span.GenAI.Anthropic.Output.Error != nil && span.GenAI.Anthropic.Output.Error.Type != "" {
					return StatusCodeError
				}
				if span.GenAI.Gemini != nil && span.GenAI.Gemini.Output.Error != nil && span.GenAI.Gemini.Output.Error.Status != "" {
					return StatusCodeError
				}
				if span.GenAI.Qwen != nil && span.GenAI.Qwen.Error.Type != "" {
					return StatusCodeError
				}
				if span.GenAI.Bedrock != nil && span.GenAI.Bedrock.Output.ErrorType != "" {
					return StatusCodeError
				}
				if span.GenAI.Rerank != nil && span.GenAI.Rerank.Output.Error != nil && span.GenAI.Rerank.Output.Error.Type != "" {
					return StatusCodeError
				}
			}

			return StatusCodeUnset
		}
	} else if span.Status < 500 {
		return StatusCodeUnset
	}

	return StatusCodeError
}

var (
	grpcStatusCodeOK               = int(grpc_codes.OK)
	grpcStatusCodeUnknown          = int(grpc_codes.Unknown)
	grpcStatusCodeDeadlineExceeded = int(grpc_codes.DeadlineExceeded)
	grpcStatusCodeUnimplemented    = int(grpc_codes.Unimplemented)
	grpcStatusCodeInternal         = int(grpc_codes.Internal)
	grpcStatusCodeUnavailable      = int(grpc_codes.Unavailable)
	grpcStatusCodeDataLoss         = int(grpc_codes.DataLoss)
)

// GrpcSpanStatusCode https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/rpc/#grpc-status
func GrpcSpanStatusCode(span *Span) string {
	if span.Type == EventTypeGRPCClient && span.Status != grpcStatusCodeOK {
		return StatusCodeError
	}
	switch span.Status {
	case grpcStatusCodeOK:
		return StatusCodeUnset
	case grpcStatusCodeUnknown, grpcStatusCodeDeadlineExceeded, grpcStatusCodeUnimplemented,
		grpcStatusCodeInternal, grpcStatusCodeUnavailable, grpcStatusCodeDataLoss:
		return StatusCodeError
	}

	return StatusCodeUnset
}

func (s *Span) RequestBodyLength() int64 {
	// The value -1 indicates that the length is unknown.
	if s.ContentLength < 0 {
		return 0
	}

	return s.ContentLength
}

func (s *Span) ResponseBodyLength() int64 {
	// The value -1 indicates that the length is unknown.
	if s.ResponseLength < 0 {
		return 0
	}

	return s.ResponseLength
}

// ServiceGraphKind returns the Kind string representation that is compliant with service graph metrics specification
func (s *Span) ServiceGraphKind() string {
	switch s.Type {
	case EventTypeHTTP, EventTypeGRPC, EventTypeKafkaServer, EventTypeMQTTServer, EventTypeNATSServer, EventTypeSunRPCServer, EventTypeRedisServer, EventTypeMemcachedServer, EventTypeSQLServer:
		return "SPAN_KIND_SERVER"
	case EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient, EventTypeRedisClient, EventTypeMongoClient, EventTypeFailedConnect, EventTypeCouchbaseClient, EventTypeMemcachedClient, EventTypeSunRPCClient:
		return "SPAN_KIND_CLIENT"
	case EventTypeKafkaClient, EventTypeMQTTClient, EventTypeNATSClient, EventTypeAMQPClient:
		switch s.Method {
		case MessagingPublish:
			return "SPAN_KIND_PRODUCER"
		case MessagingProcess:
			return "SPAN_KIND_CONSUMER"
		}
	}
	return "SPAN_KIND_INTERNAL"
}

// ServiceGraphConnectionType returns the connection_type for service graph metrics.
// See: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector
func (s *Span) ServiceGraphConnectionType() string {
	switch s.Type {
	case EventTypeSQLClient, EventTypeRedisClient, EventTypeMongoClient, EventTypeCouchbaseClient, EventTypeMemcachedClient:
		return "database"
	case EventTypeKafkaClient, EventTypeMQTTClient, EventTypeNATSClient, EventTypeAMQPClient:
		return "messaging_system"
	case EventTypeHTTPClient:
		if s.SubType == HTTPSubtypeAWSSQS {
			return "messaging_system"
		}
		if s.SubType == HTTPSubtypeElasticsearch || s.SubType == HTTPSubtypeSQLPP {
			return "database"
		}
	}
	return ""
}

func (s *Span) TraceName() string {
	if s.OverrideTraceName != "" {
		return s.OverrideTraceName
	}
	switch s.Type {
	case EventTypeHTTP, EventTypeHTTPClient:
		if s.Type == EventTypeHTTP && s.SubType == HTTPSubtypeGraphQL && s.GraphQL != nil {
			if s.GraphQL.OperationType != "" {
				return "GraphQL " + s.GraphQL.OperationType
			} else {
				return "GraphQL Operation"
			}
		}
		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeElasticsearch && s.Elasticsearch != nil {
			dbOperationName := s.Elasticsearch.DBOperationName
			// https://opentelemetry.io/docs/specs/semconv/database/database-spans/#name
			if dbOperationName == "" {
				return "elasticsearch"
			}
			switch {
			case s.Elasticsearch.DBCollectionName != "":
				return dbOperationName + " " + s.Elasticsearch.DBCollectionName
			case s.DBNamespace != "":
				return dbOperationName + " " + s.DBNamespace
			case s.Host != "" && s.HostPort != 0:
				return dbOperationName + " " + s.Host + ":" + strconv.Itoa(s.HostPort)
			default:
				return dbOperationName
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeAWSS3 && s.AWS != nil {
			if s.AWS.S3.Method != "" {
				return "s3." + s.AWS.S3.Method
			} else {
				return "s3.Operation"
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeAWSSQS && s.AWS != nil {
			if s.AWS.SQS.OperationName != "" {
				return "sqs." + s.AWS.SQS.OperationName
			} else {
				return "sqs.Operation"
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeSQLPP {
			dbOperationName := s.Method
			if dbOperationName == "" {
				return s.DBSystem
			}
			switch {
			case s.Route != "":
				return dbOperationName + " " + s.Route
			case s.DBNamespace != "":
				return dbOperationName + " " + s.DBNamespace
			case s.Host != "" && s.HostPort != 0:
				return dbOperationName + " " + s.Host + ":" + strconv.Itoa(s.HostPort)
			default:
				return dbOperationName
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeOpenAI && s.GenAI != nil && s.GenAI.OpenAI != nil {
			name := s.GenAI.OpenAI.OperationName
			if name != "" {
				switch {
				case s.GenAI.OpenAI.Request.Model != "":
					return name + " " + s.GenAI.OpenAI.Request.Model
				case s.GenAI.OpenAI.ResponseModel != "":
					return name + " " + s.GenAI.OpenAI.ResponseModel
				default:
					return name
				}
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeAnthropic && s.GenAI != nil && s.GenAI.Anthropic != nil {
			name := s.GenAI.Anthropic.Output.Type
			if name != "" {
				switch {
				case s.GenAI.Anthropic.Input.Model != "":
					return name + " " + s.GenAI.Anthropic.Input.Model
				case s.GenAI.Anthropic.Output.Model != "":
					return name + " " + s.GenAI.Anthropic.Output.Model
				default:
					return name
				}
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeGemini && s.GenAI != nil && s.GenAI.Gemini != nil {
			op := s.GenAI.Gemini.OperationName()
			model := s.GenAI.Gemini.Model
			if model != "" {
				return op + " " + model
			}
			return op
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeQwen && s.GenAI != nil && s.GenAI.Qwen != nil {
			name := s.GenAI.Qwen.OperationName
			if name != "" {
				switch {
				case s.GenAI.Qwen.Request.Model != "":
					return name + " " + s.GenAI.Qwen.Request.Model
				case s.GenAI.Qwen.ResponseModel != "":
					return name + " " + s.GenAI.Qwen.ResponseModel
				default:
					return name
				}
			}
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeAWSBedrock && s.GenAI != nil && s.GenAI.Bedrock != nil {
			if s.GenAI.Bedrock.Model != "" {
				return InvokeModelOperationName + " " + s.GenAI.Bedrock.Model
			}
			return InvokeModelOperationName
		}

		if s.SubType == HTTPSubtypeMCP && s.GenAI != nil && s.GenAI.MCP != nil {
			op := s.GenAI.MCP.OperationName()
			if s.GenAI.MCP.ToolName != "" {
				return op + " " + s.GenAI.MCP.ToolName
			}
			return op
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeEmbedding && s.GenAI != nil && s.GenAI.Embedding != nil {
			op := s.GenAI.Embedding.OperationName()
			model := s.GenAI.Embedding.Model
			if s.GenAI.Embedding.Input.Model != "" {
				model = s.GenAI.Embedding.Input.Model
			}
			if model != "" {
				return op + " " + model
			}
			return op
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeRerank && s.GenAI != nil && s.GenAI.Rerank != nil {
			model := s.GenAI.Rerank.Input.Model
			if model == "" {
				model = s.GenAI.Rerank.Output.Model
			}
			if model != "" {
				return "rerank " + model
			}
			return "rerank"
		}

		if s.Type == EventTypeHTTPClient && s.SubType == HTTPSubtypeRetrieval && s.GenAI != nil && s.GenAI.Retrieval != nil {
			if name := s.GenAI.Retrieval.GetCollection(); name != "" {
				return RetrievalOperationName + " " + name
			}
			if s.GenAI.Retrieval.Provider != "" {
				return RetrievalOperationName + " " + s.GenAI.Retrieval.Provider
			}
			return RetrievalOperationName
		}

		if s.SubType == HTTPSubtypeJSONRPC && s.JSONRPC != nil {
			if s.JSONRPC.Method != "" {
				return s.JSONRPC.Method
			}
			return "jsonrpc"
		}

		name := s.Method
		if s.Route != "" {
			name += " " + s.Route
		}
		return name
	case EventTypeGRPC, EventTypeGRPCClient:
		return s.Path
	case EventTypeSQLClient, EventTypeSQLServer:
		operation := s.Method
		if operation == "" {
			return "SQL"
		}
		table := s.Path
		if table != "" {
			operation += " " + table
		}
		return operation
	case EventTypeRedisClient, EventTypeRedisServer:
		if s.Method == "" {
			return "REDIS"
		}
		return s.Method
	case EventTypeMemcachedClient, EventTypeMemcachedServer:
		if s.Method == "" {
			return "MEMCACHED"
		}
		return s.Method
	case EventTypeKafkaClient, EventTypeKafkaServer, EventTypeMQTTClient, EventTypeMQTTServer, EventTypeNATSClient, EventTypeNATSServer, EventTypeAMQPClient:
		if s.Path == "" {
			return s.Method
		}
		return s.Method + " " + s.Path
	case EventTypeSunRPCClient, EventTypeSunRPCServer:
		if s.Path == "" {
			return "sunrpc/" + s.Method
		}
		return s.Path + "/" + s.Method
	case EventTypeMongoClient:
		if s.Path != "" && s.Method != "" {
			// TODO for database operations like listCollections, we need to use s.DbNamespace instead of s.Path
			return s.Method + " " + s.Path
		}
		if s.Path != "" {
			return s.Path
		}
		if s.Method != "" {
			return s.Method
		}
		return semconv.DBSystemNameMongoDB.Value.AsString()
	case EventTypeManualSpan:
		return s.Method
	case EventTypeFailedConnect:
		return "CONNECT"
	case EventTypeDNS:
		if s.Path == "" {
			if s.Method == "" {
				return "DNS"
			}
			return s.Method
		}
		return s.Method + " " + s.Path
	case EventTypeCouchbaseClient:
		if s.Method == "" {
			return "COUCHBASE"
		}
		if s.Path != "" {
			return s.Method + " " + s.Path
		}
		return s.Method
	}
	return ""
}

func (s *Span) isHTTPOrGRPCClient() bool {
	return s.Type == EventTypeHTTPClient || s.Type == EventTypeGRPCClient
}

func (s *Span) isMetricsExportURL() bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return strings.HasPrefix(s.Path, grpcMetricsDetectPattern)
	case EventTypeHTTPClient:
		return strings.HasSuffix(s.Path, metricsDetectPattern)
	default:
		return false
	}
}

func (s *Span) IsDNSSpan() bool {
	return s.Type == EventTypeDNS
}

func (s *Span) isTracesExportURL() bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return strings.HasPrefix(s.Path, grpcTracesDetectPattern)
	case EventTypeHTTPClient:
		return strings.HasSuffix(s.Path, tracesDetectPattern)
	default:
		return false
	}
}

func (s *Span) sendsOnDefaultGrpcOtelPort(defaultOtlpGRPCPort int) bool {
	otlpPort, ok := s.portFromEndpointEnvVar(envOTLPEndpoint)
	if ok {
		return otlpPort == s.PeerPort
	}
	return s.PeerPort == defaultOtlpGRPCPort
}

func (s *Span) sendsTracesOnGrpcOtelPort(defaultOtlpGRPCPort int) bool {
	otlpTracesProtocol, ok := s.Service.EnvVars[envOTLPTracesProtocol]
	if ok && otlpTracesProtocol != otlpGrpcProtocol {
		return false
	}
	otlpProtocol, ok := s.Service.EnvVars[envOTLPProtocol]
	if ok && otlpProtocol != otlpGrpcProtocol {
		return false
	}
	otlpTracesPort, ok := s.portFromEndpointEnvVar(envOTLPTracesEndpoint)
	if ok {
		return otlpTracesPort == s.PeerPort
	}
	return s.sendsOnDefaultGrpcOtelPort(defaultOtlpGRPCPort)
}

func (s *Span) sendsMetricsOnOtelPort(defaultOtlpGRPCPort int) bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return s.sendsMetricsOnGrpcOtelPort(defaultOtlpGRPCPort)
	default:
		return false
	}
}

func (s *Span) sendsTracesOnOtelPort(defaultOtlpGRPCPort int) bool {
	switch s.Type {
	case EventTypeGRPCClient:
		return s.sendsTracesOnGrpcOtelPort(defaultOtlpGRPCPort)
	default:
		return false
	}
}

func (s *Span) sendsMetricsOnGrpcOtelPort(defaultOtlpGRPCPort int) bool {
	otlpMetricsProtocol, ok := s.Service.EnvVars[envOTLPMetricsProtocol]
	if ok && otlpMetricsProtocol != otlpGrpcProtocol {
		return false
	}
	otlpProtocol, ok := s.Service.EnvVars[envOTLPProtocol]
	if ok && otlpProtocol != otlpGrpcProtocol {
		return false
	}
	otlpMetricsPort, ok := s.portFromEndpointEnvVar(envOTLPMetricsEndpoint)
	if ok {
		return otlpMetricsPort == s.PeerPort
	}
	return s.sendsOnDefaultGrpcOtelPort(defaultOtlpGRPCPort)
}

func (s *Span) portFromEndpointEnvVar(envVarName string) (int, bool) {
	endpoint, ok := s.Service.EnvVars[envVarName]
	if !ok {
		return 0, false
	}
	parsedURL, err := url.Parse(endpoint)
	if err != nil || parsedURL == nil {
		return 0, false
	}
	port, err := strconv.Atoi(parsedURL.Port())
	if err != nil {
		return 0, false
	}
	return port, true
}

func (s *Span) IsExportMetricsSpan(defaultOtlpGRPCPort int) bool {
	// check if it's a successful client call
	if !s.isHTTPOrGRPCClient() || (SpanStatusCode(s) != StatusCodeUnset) {
		return false
	}

	return s.isMetricsExportURL() || s.sendsMetricsOnOtelPort(defaultOtlpGRPCPort)
}

func (s *Span) IsExportTracesSpan(defaultOtlpGRPCPort int) bool {
	// check if it's a successful client call
	if !s.isHTTPOrGRPCClient() || (SpanStatusCode(s) != StatusCodeUnset) {
		return false
	}

	return s.isTracesExportURL() || s.sendsTracesOnOtelPort(defaultOtlpGRPCPort)
}

func (s *Span) IsSelfReferenceSpan() bool {
	return s.Peer == s.Host && (s.Service.UID.Namespace == s.OtherNamespace || s.OtherNamespace == "")
}

func (s *Span) DBSystemName() attribute.KeyValue {
	if s.Type == EventTypeSQLClient || s.Type == EventTypeSQLServer {
		switch s.SubType {
		case int(DBPostgres):
			return semconv.DBSystemNamePostgreSQL
		case int(DBMySQL):
			return semconv.DBSystemNameMySQL
		case int(DBMSSQL):
			return semconv.DBSystemNameMicrosoftSQLServer
		}
	}

	return semconv.DBSystemNameOtherSQL
}

func (s *Span) HasOriginalHost() bool {
	schemeHost := strings.Split(s.Statement, SchemeHostSeparator)
	return len(schemeHost) > 1 && schemeHost[1] != ""
}

func (s *Span) GenAIInputTokens() int {
	if s.GenAI == nil {
		return 0
	}

	if s.GenAI.OpenAI != nil {
		return s.GenAI.OpenAI.Usage.GetInputTokens()
	}

	if s.GenAI.Anthropic != nil {
		// Per Anthropic semconv: input_tokens excludes cached tokens.
		// Total = input_tokens + cache_read + cache_creation.
		u := s.GenAI.Anthropic.Output.Usage
		return u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens
	}

	if s.GenAI.Gemini != nil {
		return s.GenAI.Gemini.Output.UsageMetadata.PromptTokenCount
	}

	if s.GenAI.Qwen != nil {
		return s.GenAI.Qwen.Usage.GetInputTokens()
	}

	if s.GenAI.Bedrock != nil {
		return s.GenAI.Bedrock.Output.InputTokens
	}

	if s.GenAI.Embedding != nil {
		return s.GenAI.Embedding.GetInputTokens()
	}

	if s.GenAI.Rerank != nil {
		return s.GenAI.Rerank.Output.GetTotalTokens()
	}

	if s.GenAI.Retrieval != nil {
		return s.GenAI.Retrieval.GetInputTokens()
	}

	return 0
}

func (s *Span) GenAIOutputTokens() int {
	if s.GenAI == nil {
		return 0
	}

	if s.GenAI.OpenAI != nil {
		return s.GenAI.OpenAI.Usage.GetOutputTokens()
	}

	if s.GenAI.Anthropic != nil {
		return s.GenAI.Anthropic.Output.Usage.OutputTokens
	}

	if s.GenAI.Gemini != nil {
		return s.GenAI.Gemini.Output.UsageMetadata.CandidatesTokenCount
	}

	if s.GenAI.Qwen != nil {
		return s.GenAI.Qwen.Usage.GetOutputTokens()
	}

	if s.GenAI.Bedrock != nil {
		return s.GenAI.Bedrock.Output.OutputTokens
	}

	if s.GenAI.Embedding != nil {
		return s.GenAI.Embedding.GetOutputTokens()
	}

	return 0
}

func (s *Span) GenAIOperationName() string {
	if s.GenAI == nil {
		return ""
	}
	if s.GenAI.OpenAI != nil {
		return s.GenAI.OpenAI.OperationName
	}
	if s.GenAI.Anthropic != nil {
		return s.GenAI.Anthropic.Output.Type
	}
	if s.GenAI.Gemini != nil {
		return s.GenAI.Gemini.OperationName()
	}
	if s.GenAI.Qwen != nil {
		return s.GenAI.Qwen.OperationName
	}
	if s.GenAI.Bedrock != nil {
		return InvokeModelOperationName
	}
	if s.GenAI.Embedding != nil {
		return s.GenAI.Embedding.OperationName()
	}
	if s.GenAI.Rerank != nil {
		return "rerank"
	}
	if s.GenAI.Retrieval != nil {
		return s.GenAI.Retrieval.OperationName()
	}
	return ""
}

func (s *Span) GenAIProviderName() string {
	if s.GenAI == nil {
		return ""
	}
	if s.GenAI.OpenAI != nil {
		return semconv.GenAIProviderNameOpenAI.Value.AsString()
	}
	if s.GenAI.Anthropic != nil {
		return semconv.GenAIProviderNameAnthropic.Value.AsString()
	}
	if s.GenAI.Gemini != nil {
		return semconv.GenAIProviderNameGCPGemini.Value.AsString()
	}
	if s.GenAI.Qwen != nil {
		return attr.QwenProviderName
	}
	if s.GenAI.Bedrock != nil {
		return semconv.GenAIProviderNameAWSBedrock.Value.AsString()
	}
	if s.GenAI.Embedding != nil {
		return s.GenAI.Embedding.Provider
	}
	if s.GenAI.Rerank != nil {
		return s.GenAI.Rerank.Provider
	}
	if s.GenAI.Retrieval != nil {
		return s.GenAI.Retrieval.Provider
	}
	return ""
}

func (s *Span) GenAIRequestModel() string {
	if s.GenAI == nil {
		return ""
	}
	if s.GenAI.OpenAI != nil {
		return s.GenAI.OpenAI.Request.Model
	}
	if s.GenAI.Anthropic != nil {
		return s.GenAI.Anthropic.Input.Model
	}
	if s.GenAI.Gemini != nil {
		return s.GenAI.Gemini.Model
	}
	if s.GenAI.Qwen != nil {
		return s.GenAI.Qwen.Request.Model
	}
	if s.GenAI.Bedrock != nil {
		return s.GenAI.Bedrock.Model
	}
	if s.GenAI.Embedding != nil {
		if s.GenAI.Embedding.Input.Model != "" {
			return s.GenAI.Embedding.Input.Model
		}
		return s.GenAI.Embedding.Model
	}
	if s.GenAI.Rerank != nil {
		return s.GenAI.Rerank.Input.Model
	}
	if s.GenAI.Retrieval != nil {
		return s.GenAI.Retrieval.Input.Model
	}
	return ""
}

func (s *Span) GenAIResponseModel() string {
	if s.GenAI == nil {
		return ""
	}
	if s.GenAI.OpenAI != nil {
		return s.GenAI.OpenAI.ResponseModel
	}
	if s.GenAI.Anthropic != nil {
		return s.GenAI.Anthropic.Output.Model
	}
	if s.GenAI.Gemini != nil {
		if s.GenAI.Gemini.Output.ModelVersion != "" {
			return s.GenAI.Gemini.Output.ModelVersion
		}
		return s.GenAI.Gemini.Model
	}
	if s.GenAI.Qwen != nil {
		if s.GenAI.Qwen.ResponseModel != "" {
			return s.GenAI.Qwen.ResponseModel
		}
		return s.GenAI.Qwen.Request.Model
	}
	if s.GenAI.Bedrock != nil {
		return s.GenAI.Bedrock.Model
	}
	if s.GenAI.Embedding != nil {
		if s.GenAI.Embedding.Output.Model != "" {
			return s.GenAI.Embedding.Output.Model
		}
		return s.GenAI.Embedding.Model
	}
	if s.GenAI.Rerank != nil {
		if s.GenAI.Rerank.Output.Model != "" {
			return s.GenAI.Rerank.Output.Model
		}
		return s.GenAI.Rerank.Input.Model
	}
	if s.GenAI.Retrieval != nil {
		if s.GenAI.Retrieval.Output.Model != "" {
			return s.GenAI.Retrieval.Output.Model
		}
		return s.GenAI.Retrieval.Input.Model
	}
	return ""
}
