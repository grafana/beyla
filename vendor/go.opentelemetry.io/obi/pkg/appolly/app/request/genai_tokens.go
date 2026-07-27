// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"math"
	"strconv"

	jsoniter "github.com/json-iterator/go"
)

var tokenJSON = jsoniter.ConfigCompatibleWithStandardLibrary

// TokenCount retains a valid non-negative token count and whether the provider
// reported it. Its zero value represents an unavailable count.
type TokenCount struct {
	value    int
	reported bool
}

// NewTokenCount creates a reported token count. Negative values produce an
// unavailable count.
func NewTokenCount(value int) TokenCount {
	var count TokenCount
	count.set(value)
	return count
}

func (c *TokenCount) set(value int) {
	if value < 0 {
		*c = TokenCount{}
		return
	}
	c.value = value
	c.reported = true
}

// Get returns the token count and whether it was reported.
func (c TokenCount) Get() (int, bool) {
	return c.value, c.reported
}

// Merge replaces the count when the provider reported a newer value.
func (c *TokenCount) Merge(other TokenCount) {
	if other.reported {
		*c = other
	}
}

func (c *TokenCount) UnmarshalJSON(data []byte) error {
	*c = TokenCount{}
	value, err := strconv.Atoi(string(data))
	if err != nil {
		return nil
	}
	c.set(value)
	return nil
}

func (c TokenCount) MarshalJSON() ([]byte, error) {
	if !c.reported {
		return []byte("null"), nil
	}
	return []byte(strconv.Itoa(c.value)), nil
}

func decodeTokenFields(data []byte, value any) {
	_ = tokenJSON.Unmarshal(data, value)
}

func decodeTokenField(data []byte, path ...any) TokenCount {
	field := tokenJSON.Get(data, path...)
	if field.ValueType() != jsoniter.NumberValue {
		return TokenCount{}
	}
	var count TokenCount
	_ = count.UnmarshalJSON([]byte(field.ToString()))
	return count
}

func (d *OpenAIInputTokensDetails) UnmarshalJSON(data []byte) error {
	d.CachedTokens = decodeTokenField(data, "cached_tokens")
	d.CacheCreationTokens = decodeTokenField(data, "cache_creation_tokens")
	d.AudioTokens = decodeTokenField(data, "audio_tokens")
	return nil
}

func (d *OpenAIInputTokensDetails) merge(other OpenAIInputTokensDetails) {
	d.CachedTokens.Merge(other.CachedTokens)
	d.CacheCreationTokens.Merge(other.CacheCreationTokens)
	d.AudioTokens.Merge(other.AudioTokens)
}

func (d *OpenAIOutputTokensDetails) UnmarshalJSON(data []byte) error {
	d.ReasoningTokens = decodeTokenField(data, "reasoning_tokens")
	d.AudioTokens = decodeTokenField(data, "audio_tokens")
	d.AcceptedPredictionTokens = decodeTokenField(data, "accepted_prediction_tokens")
	d.RejectedPredictionTokens = decodeTokenField(data, "rejected_prediction_tokens")
	return nil
}

func (d *OpenAIOutputTokensDetails) merge(other OpenAIOutputTokensDetails) {
	d.ReasoningTokens.Merge(other.ReasoningTokens)
	d.AudioTokens.Merge(other.AudioTokens)
	d.AcceptedPredictionTokens.Merge(other.AcceptedPredictionTokens)
	d.RejectedPredictionTokens.Merge(other.RejectedPredictionTokens)
}

func (u *OpenAIUsage) UnmarshalJSON(data []byte) error {
	*u = OpenAIUsage{}
	u.InputTokens = decodeTokenField(data, "input_tokens")
	u.OutputTokens = decodeTokenField(data, "output_tokens")
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	u.CompletionTokens = decodeTokenField(data, "completion_tokens")

	var details struct {
		InputDetails  *OpenAIInputTokensDetails  `json:"input_tokens_details"`
		InputAliases  *OpenAIInputTokensDetails  `json:"prompt_tokens_details"`
		OutputDetails *OpenAIOutputTokensDetails `json:"output_tokens_details"`
		OutputAliases *OpenAIOutputTokensDetails `json:"completion_tokens_details"`
	}
	decodeTokenFields(data, &details)
	u.InputDetails = details.InputAliases
	if details.InputDetails != nil {
		if u.InputDetails == nil {
			u.InputDetails = &OpenAIInputTokensDetails{}
		}
		u.InputDetails.merge(*details.InputDetails)
	}
	u.OutputDetails = details.OutputAliases
	if details.OutputDetails != nil {
		if u.OutputDetails == nil {
			u.OutputDetails = &OpenAIOutputTokensDetails{}
		}
		u.OutputDetails.merge(*details.OutputDetails)
	}
	return nil
}

func (u *OpenAIUsage) InputTokenCount() (int, bool) {
	if tokens, reported := u.InputTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := u.PromptTokens.Get(); reported {
		return tokens, true
	}
	return 0, false
}

func (u *OpenAIUsage) OutputTokenCount() (int, bool) {
	if tokens, reported := u.OutputTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := u.CompletionTokens.Get(); reported {
		return tokens, true
	}
	if total, totalReported := u.TotalTokens.Get(); totalReported {
		if input, inputReported := u.InputTokenCount(); inputReported && total >= input {
			return total - input, true
		}
	}
	return 0, false
}

func (u *OpenAIUsage) Merge(other OpenAIUsage) {
	u.InputTokens.Merge(other.InputTokens)
	u.OutputTokens.Merge(other.OutputTokens)
	u.TotalTokens.Merge(other.TotalTokens)
	u.PromptTokens.Merge(other.PromptTokens)
	u.CompletionTokens.Merge(other.CompletionTokens)

	if other.OutputDetails != nil {
		if u.OutputDetails == nil {
			u.OutputDetails = &OpenAIOutputTokensDetails{}
		}
		u.OutputDetails.merge(*other.OutputDetails)
	}
	if other.InputDetails != nil {
		if u.InputDetails == nil {
			u.InputDetails = &OpenAIInputTokensDetails{}
		}
		u.InputDetails.merge(*other.InputDetails)
	}
}

func (d *AnthropicCacheCreation) UnmarshalJSON(data []byte) error {
	d.Ephemeral5mInputTokens = decodeTokenField(data, "ephemeral_5m_input_tokens")
	d.Ephemeral1hInputTokens = decodeTokenField(data, "ephemeral_1h_input_tokens")
	return nil
}

func (d *AnthropicCacheCreation) merge(other AnthropicCacheCreation) {
	d.Ephemeral5mInputTokens.Merge(other.Ephemeral5mInputTokens)
	d.Ephemeral1hInputTokens.Merge(other.Ephemeral1hInputTokens)
}

func (u *AnthropicUsage) UnmarshalJSON(data []byte) error {
	var decoded struct {
		ServiceTier  string `json:"service_tier"`
		InferenceGeo string `json:"inference_geo"`
	}
	decodeTokenFields(data, &decoded)

	*u = AnthropicUsage{
		ServiceTier:  decoded.ServiceTier,
		InferenceGeo: decoded.InferenceGeo,
	}
	u.InputTokens = decodeTokenField(data, "input_tokens")
	u.OutputTokens = decodeTokenField(data, "output_tokens")
	u.CacheCreationInputTokens = decodeTokenField(data, "cache_creation_input_tokens")
	u.CacheReadInputTokens = decodeTokenField(data, "cache_read_input_tokens")
	u.ReasoningOutputTokens = decodeTokenField(data, "reasoning_output_tokens")
	var cache struct {
		CacheCreation *AnthropicCacheCreation `json:"cache_creation"`
	}
	decodeTokenFields(data, &cache)
	u.CacheCreation = cache.CacheCreation
	return nil
}

func (u *AnthropicUsage) InputTokenCount() (int, bool) {
	return sumTokenCounts(
		u.InputTokens,
		u.CacheCreationInputTokens,
		u.CacheReadInputTokens,
	)
}

func sumTokenCounts(counts ...TokenCount) (int, bool) {
	total := 0
	reported := false
	for _, count := range counts {
		if value, ok := count.Get(); ok {
			if value > math.MaxInt-total {
				return 0, false
			}
			total += value
			reported = true
		}
	}
	return total, reported
}

func (u *AnthropicUsage) OutputTokenCount() (int, bool) {
	return u.OutputTokens.Get()
}

func (u *AnthropicUsage) Merge(other AnthropicUsage) {
	u.InputTokens.Merge(other.InputTokens)
	u.OutputTokens.Merge(other.OutputTokens)
	u.CacheCreationInputTokens.Merge(other.CacheCreationInputTokens)
	u.CacheReadInputTokens.Merge(other.CacheReadInputTokens)
	u.ReasoningOutputTokens.Merge(other.ReasoningOutputTokens)
	if other.CacheCreation != nil {
		if u.CacheCreation == nil {
			u.CacheCreation = &AnthropicCacheCreation{}
		}
		u.CacheCreation.merge(*other.CacheCreation)
	}
}

func (u *GeminiUsage) UnmarshalJSON(data []byte) error {
	*u = GeminiUsage{}
	u.PromptTokenCount = decodeTokenField(data, "promptTokenCount")
	u.CandidatesTokenCount = decodeTokenField(data, "candidatesTokenCount")
	u.TotalTokenCount = decodeTokenField(data, "totalTokenCount")
	u.ToolUsePromptTokenCount = decodeTokenField(data, "toolUsePromptTokenCount")
	u.ThoughtsTokenCount = decodeTokenField(data, "thoughtsTokenCount")
	u.CachedContentTokenCount = decodeTokenField(data, "cachedContentTokenCount")
	var promptDetails struct {
		Value []GeminiModalityTokenCount `json:"promptTokensDetails"`
	}
	decodeTokenFields(data, &promptDetails)
	u.PromptTokensDetails = promptDetails.Value
	var cacheDetails struct {
		Value []GeminiModalityTokenCount `json:"cacheTokensDetails"`
	}
	decodeTokenFields(data, &cacheDetails)
	u.CacheTokensDetails = cacheDetails.Value
	var candidateDetails struct {
		Value []GeminiModalityTokenCount `json:"candidatesTokensDetails"`
	}
	decodeTokenFields(data, &candidateDetails)
	u.CandidatesTokensDetails = candidateDetails.Value
	var toolDetails struct {
		Value []GeminiModalityTokenCount `json:"toolUsePromptTokensDetails"`
	}
	decodeTokenFields(data, &toolDetails)
	u.ToolUsePromptTokensDetails = toolDetails.Value
	return nil
}

func (d *GeminiModalityTokenCount) UnmarshalJSON(data []byte) error {
	type plain GeminiModalityTokenCount
	var decoded plain
	decodeTokenFields(data, &decoded)

	*d = GeminiModalityTokenCount(decoded)
	d.TokenCount = decodeTokenField(data, "tokenCount")
	return nil
}

func (u *GeminiUsage) InputTokenCount() (int, bool) {
	return sumTokenCounts(u.PromptTokenCount, u.ToolUsePromptTokenCount)
}

func (u *GeminiUsage) OutputTokenCount() (int, bool) {
	return sumTokenCounts(u.CandidatesTokenCount, u.ThoughtsTokenCount)
}

func (u *GeminiUsage) Merge(other GeminiUsage) {
	u.PromptTokenCount.Merge(other.PromptTokenCount)
	u.CandidatesTokenCount.Merge(other.CandidatesTokenCount)
	u.TotalTokenCount.Merge(other.TotalTokenCount)
	u.ToolUsePromptTokenCount.Merge(other.ToolUsePromptTokenCount)
	u.ThoughtsTokenCount.Merge(other.ThoughtsTokenCount)
	u.CachedContentTokenCount.Merge(other.CachedContentTokenCount)
	mergeGeminiTokenDetails(&u.PromptTokensDetails, other.PromptTokensDetails)
	mergeGeminiTokenDetails(&u.CacheTokensDetails, other.CacheTokensDetails)
	mergeGeminiTokenDetails(&u.CandidatesTokensDetails, other.CandidatesTokensDetails)
	mergeGeminiTokenDetails(&u.ToolUsePromptTokensDetails, other.ToolUsePromptTokensDetails)
}

func mergeGeminiTokenDetails(current *[]GeminiModalityTokenCount, other []GeminiModalityTokenCount) {
	for _, incoming := range other {
		found := false
		for i := range *current {
			if (*current)[i].Modality == incoming.Modality {
				(*current)[i].TokenCount.Merge(incoming.TokenCount)
				found = true
				break
			}
		}
		if !found {
			*current = append(*current, incoming)
		}
	}
}

func (b *BedrockResponse) InputTokenCount() (int, bool) {
	base := b.InputTokens
	if _, reported := base.Get(); !reported {
		base = b.Usage.InputTokens
		if _, reported := base.Get(); !reported {
			base = b.PromptTokenCount
		}
	}
	return sumTokenCounts(base, b.Usage.CacheReadInputTokens, b.Usage.CacheWriteInputTokens)
}

func (b *BedrockResponse) OutputTokenCount() (int, bool) {
	if tokens, reported := b.OutputTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := b.Usage.OutputTokens.Get(); reported {
		return tokens, true
	}
	return b.GenerationTokenCount.Get()
}

func (u *BedrockUsage) UnmarshalJSON(data []byte) error {
	*u = BedrockUsage{}
	u.InputTokens = firstTokenCount(
		decodeTokenField(data, "inputTokens"),
		decodeTokenField(data, "input_tokens"),
	)
	u.OutputTokens = firstTokenCount(
		decodeTokenField(data, "outputTokens"),
		decodeTokenField(data, "output_tokens"),
	)
	u.TotalTokens = firstTokenCount(
		decodeTokenField(data, "totalTokens"),
		decodeTokenField(data, "total_tokens"),
	)
	u.CacheReadInputTokens = firstTokenCount(
		decodeTokenField(data, "cacheReadInputTokens"),
		decodeTokenField(data, "cache_read_input_tokens"),
	)
	u.CacheWriteInputTokens = firstTokenCount(
		decodeTokenField(data, "cacheWriteInputTokens"),
		decodeTokenField(data, "cache_creation_input_tokens"),
	)
	var cacheDetails struct {
		Value []BedrockCacheDetail `json:"cacheDetails"`
	}
	decodeTokenFields(data, &cacheDetails)
	u.CacheDetails = cacheDetails.Value
	var cacheCreation struct {
		Value *AnthropicCacheCreation `json:"cache_creation"`
	}
	decodeTokenFields(data, &cacheCreation)
	u.CacheCreation = cacheCreation.Value
	return nil
}

func (d *BedrockCacheDetail) UnmarshalJSON(data []byte) error {
	var decoded struct {
		TTL string `json:"ttl"`
	}
	decodeTokenFields(data, &decoded)

	*d = BedrockCacheDetail{TTL: decoded.TTL}
	d.InputTokens = decodeTokenField(data, "inputTokens")
	return nil
}

func firstTokenCount(counts ...TokenCount) TokenCount {
	for _, count := range counts {
		if _, reported := count.Get(); reported {
			return count
		}
	}
	return TokenCount{}
}

func (u *EmbeddingUsage) UnmarshalJSON(data []byte) error {
	*u = EmbeddingUsage{}
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	return nil
}

func (u *CohereBilledUnits) UnmarshalJSON(data []byte) error {
	*u = CohereBilledUnits{}
	u.InputTokens = decodeTokenField(data, "input_tokens")
	return nil
}

func (e *VendorEmbedding) InputTokenCount() (int, bool) {
	usage := &e.Output.Usage
	if tokens, reported := usage.PromptTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := usage.TotalTokens.Get(); reported {
		return tokens, true
	}
	if e.Output.Meta != nil && e.Output.Meta.BilledUnits != nil {
		billed := e.Output.Meta.BilledUnits
		return billed.InputTokens.Get()
	}
	return 0, false
}

func (u *RerankUsage) UnmarshalJSON(data []byte) error {
	type plain RerankUsage
	var decoded plain
	decodeTokenFields(data, &decoded)

	*u = RerankUsage(decoded)
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	return nil
}

func (u *RerankMetaTokens) UnmarshalJSON(data []byte) error {
	*u = RerankMetaTokens{}
	u.InputTokens = decodeTokenField(data, "input_tokens")
	return nil
}

func (r *RerankResponse) InputTokenCount() (int, bool) {
	if tokens, reported := r.Usage.TotalTokens.Get(); reported {
		return tokens, true
	}
	if tokens, reported := r.Usage.PromptTokens.Get(); reported {
		return tokens, true
	}
	if r.Meta != nil && r.Meta.Tokens != nil {
		tokens := r.Meta.Tokens
		return tokens.InputTokens.Get()
	}
	return 0, false
}

func (u *RetrievalUsage) UnmarshalJSON(data []byte) error {
	*u = RetrievalUsage{}
	u.TotalTokens = decodeTokenField(data, "total_tokens")
	u.PromptTokens = decodeTokenField(data, "prompt_tokens")
	return nil
}

func (r *VendorRetrieval) InputTokenCount() (int, bool) {
	usage := &r.Output.Usage
	if tokens, reported := usage.PromptTokens.Get(); reported {
		return tokens, true
	}
	return usage.TotalTokens.Get()
}
