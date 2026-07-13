// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package main implements a mock OpenAI API server for integration testing.
// It responds to POST /v1/responses and /v1/chat/completions with the same headers and gzip-compressed
// body that the real OpenAI API returns.
package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const responseBody = `{
  "id": "resp_09687a288637e2be006998ad7af05481a2bb0938f77da5a9db",
  "object": "response",
  "created_at": 1771613562,
  "status": "completed",
  "background": false,
  "billing": {
    "payer": "developer"
  },
  "completed_at": 1771613572,
  "error": null,
  "frequency_penalty": 0.0,
  "incomplete_details": null,
  "instructions": "You are a coding assistant that talks like a pirate.",
  "max_output_tokens": null,
  "max_tool_calls": null,
  "model": "gpt-5-mini-2025-08-07",
  "output": [
    {
      "id": "rs_09687a288637e2be006998ad7b981481a2b2e00dde500b0d5d",
      "type": "reasoning",
      "summary": []
    },
    {
      "id": "msg_09687a288637e2be006998ad810cc881a2b84e1ea5a5decd75",
      "type": "message",
      "status": "completed",
      "content": [
        {
          "type": "output_text",
          "annotations": [],
          "logprobs": [],
          "text": "Arrr! To check if an object be an instance of a class in Python, use isinstance."
        }
      ],
      "role": "assistant"
    }
  ],
  "parallel_tool_calls": true,
  "presence_penalty": 0.0,
  "previous_response_id": null,
  "reasoning": {
    "effort": "medium",
    "summary": null
  },
  "service_tier": "default",
  "store": true,
  "temperature": 1.0,
  "tool_choice": "auto",
  "tools": [],
  "top_p": 1.0,
  "truncation": "disabled",
  "usage": {
    "input_tokens": 36,
    "input_tokens_details": {
      "cached_tokens": 0
    },
    "output_tokens": 691,
    "output_tokens_details": {
      "reasoning_tokens": 448
    },
    "total_tokens": 727
  },
  "user": null,
  "metadata": {}
}`

const errorBody = `
{
    "error": {
        "message": "You exceeded your current quota, please check your plan and billing details. For more information on this error, read the docs: https://platform.openai.com/docs/guides/error-codes/api-errors.",
        "type": "insufficient_quota",
        "param": null,
        "code": "insufficient_quota"
    }
}`

const completionsBody = `
{
  "id": "chatcmpl-DBTg5Ms2mJhaAhZ56Wq8QSf2djw3S",
  "object": "chat.completion",
  "created": 1771628061,
  "model": "gpt-4o-mini-2024-07-18",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "I now can give a great answer  \nFinal Answer: \n\n**Comprehensive Travel Report for a 6-Day Luxury Trip to London, UK**\n\n**1. Best Time to Visit and Weather Conditions:**\nThe ideal time to visit London is during late spring (May to early June) and early autumn (September to October) when the weather is mild and pleasant. During these months, temperatures generally range from 15°C to 20°C (59°F to 68°F). Rain is possible at any time of the year, so packing a light raincoat or umbrella is recommended.\n\n**2. Top Attractions and Must-See Places:**\n- **The British Museum:** A world-renowned museum offering free entry, showcasing a vast collection of art and antiquities.\n- **The Tower of London:** Explore this historic castle, home to the Crown Jewels and steeped in royal history.\n- **Buckingham Palace:** Witness the Changing of the Guard and explore the beautiful surrounding gardens.\n- **The Shard:** Enjoy breathtaking views of London from the tallest building in the UK.\n- **West End Theater District:** Catch a luxurious show at one of London's famous theaters.\n- **Borough Market:** A food lover's paradise with gourmet offerings and local delicacies.\n- **Kensington Palace:** Visit the stunning royal residence and its beautiful gardens.\n\n**3. Transportation Options:**\n- **Airports:** London is served by several airports, including Heathrow (LHR), Gatwick (LGW), and London City Airport (LCY). Heathrow is the main international airport and is about 15 miles from Central London.\n- **Local Transport:** The London Underground (Tube) is the most efficient way to navigate the city. A contactless Oyster Card or contactless payment methods are recommended for easy travel. Buses, taxis, and riverboats are also excellent options for getting around.\n\n**4. Accommodation Areas and Recommendations:**\nFor a luxury experience, consider staying in the following areas:\n- **Mayfair:** Known for upscale hotels, fine dining, and luxury shopping.\n  - Recommended: The Dorchester or Claridge's.\n- **Kensington:** Offers beautiful parks and close proximity to major attractions.\n  - Recommended: The Milestone Hotel or The Baglioni Hotel.\n- **Covent Garden:** A vibrant area with entertainment, dining, and shopping.\n  - Recommended: The Henrietta Hotel or the Covent Garden Hotel.\n\n**5. Local Customs and Cultural Considerations:**\n- **Tipping:** A 10-15% tip is customary in restaurants, though many establishments include service charges.\n- **Queuing:** The British are known for their orderly queuing; wait your turn patiently.\n- **Politeness:** Saying “please” and “thank you” is essential in British culture.\n\n**6. Safety Information and Travel Requirements:**\nLondon is generally safe for tourists, but standard precautions should be taken, such as avoiding poorly lit areas at night. As of October 2023, ensure to check for any travel advisories or entry requirements related to health, such as vaccinations or documentation.\n\n**7. Currency and Payment Methods:**\nThe currency used is the British Pound Sterling (GBP). Credit and debit cards are widely accepted, and contactless payments are very common. It's advisable to carry some cash for smaller purchases. ATMs are readily available.\n\n**8. Language Considerations:**\nThe primary language spoken is English. While most locals are fluent in English, having a few basic phrases can enhance your experience.\n\n**Final Notes:**\nWith a budget of $4400 for three travelers for six days in London, you can enjoy luxurious accommodations, gourmet dining experiences, and entrance to various attractions. Plan for a mix of fine dining and local food experiences at places like Dishoom (Indian), Sketch (high tea), and The Ivy (British cuisine). \n\nThis comprehensive travel report should serve as a valuable guide for your luxury trip to London, ensuring you experience the best that this vibrant city has to offer. Enjoy your adventure!",
        "refusal": null,
        "annotations": []
      },
      "logprobs": null,
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 396,
    "completion_tokens": 816,
    "total_tokens": 1212,
    "prompt_tokens_details": {
      "cached_tokens": 0,
      "audio_tokens": 0
    },
    "completion_tokens_details": {
      "reasoning_tokens": 0,
      "audio_tokens": 0,
      "accepted_prediction_tokens": 0,
      "rejected_prediction_tokens": 0
    }
  },
  "service_tier": "default",
  "system_fingerprint": "fp_373a14eb6f"
}
`

const conversationBody = `
{
  "id": "conv_699c949418b08194ba11beed9ba85d9607f4edeb470fde91",
  "object": "conversation",
  "created_at": 1771869332,
  "metadata": {
    "topic": "python-help",
    "user": "nino"
  }
}
`

const embeddingsBody = `{
  "object": "list",
  "data": [
    {
      "object": "embedding",
      "embedding": [0.0023064255, -0.009327292],
      "index": 0
    }
  ],
  "model": "text-embedding-3-small",
  "usage": {
    "prompt_tokens": 5,
    "total_tokens": 5
  }
}`

type responsesRequest struct {
	Input        string `json:"input"`
	Instructions string `json:"instructions"`
	Model        string `json:"model"`
}

func setResponseHeaders(h http.Header) {
	h.Set("X-Ratelimit-Limit-Tokens", "500000")
	h.Set("X-Ratelimit-Reset-Requests", "120ms")
	h.Set("X-Ratelimit-Reset-Tokens", "56ms")
	h.Set("X-Ratelimit-Remaining-Tokens", "499526")
	h.Set("X-Ratelimit-Remaining-Requests", "499")
	h.Set("X-Ratelimit-Limit-Requests", "500")
	h.Set("X-Request-Id", "req_a4bd76e7bcfc4ba4aa69aa906769538f")
	h.Set("Cf-Cache-Status", "DYNAMIC")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Type", "application/json")
	h.Set("Openai-Project", "proj_HKghDmlTiTtE4xukGeSiuu2s")
	h.Set("Openai-Processing-Ms", "9377")
	h.Set("Openai-Version", "2020-10-01")
	h.Set("Openai-Organization", "user-kunmtqznir9mbekxyegxrwo8")
	h.Set("Cf-Ray", "9d1033dc5d83a641-YYZ")
	h.Set("Server", "cloudflare")
	h.Set("Alt-Svc", `h3=":443"; ma=86400`)
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("Connection", "keep-alive")
}

func handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req responsesRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	var validationErrors []string
	if req.Input == "" {
		validationErrors = append(validationErrors, "input cannot be empty")
	}
	if req.Instructions == "" {
		validationErrors = append(validationErrors, "instructions cannot be empty")
	}
	if req.Model == "" {
		validationErrors = append(validationErrors, "model cannot be empty")
	}
	if len(validationErrors) > 0 {
		http.Error(w, "request validation failed:\n"+strings.Join(validationErrors, "\n"), http.StatusBadRequest)
		return
	}

	if r.URL.Query().Has("error") {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Openai-Version", "2020-10-01")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(errorBody))
		return
	}

	h := w.Header()
	setResponseHeaders(h)
	w.WriteHeader(http.StatusOK)

	gz := gzip.NewWriter(w)
	if _, err := gz.Write([]byte(responseBody)); err != nil {
		log.Printf("error writing gzip body: %v", err)
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("error closing gzip writer: %v", err)
	}
}

type completionsRequest struct {
	Messages    json.RawMessage `json:"messages"`
	Model       string          `json:"model"`
	Temperature float64         `json:"temperature"`
}

func handleCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req completionsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	var validationErrors []string
	if len(req.Messages) == 0 {
		validationErrors = append(validationErrors, "messages cannot be empty")
	}
	if req.Temperature == 0 {
		validationErrors = append(validationErrors, "temperature cannot be empty")
	}
	if req.Model == "" {
		validationErrors = append(validationErrors, "model cannot be empty")
	}
	if len(validationErrors) > 0 {
		http.Error(w, "request validation failed:\n"+strings.Join(validationErrors, "\n"), http.StatusBadRequest)
		return
	}

	if r.URL.Query().Has("error") {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Openai-Version", "2020-10-01")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(errorBody))
		return
	}

	h := w.Header()
	setResponseHeaders(h)
	w.WriteHeader(http.StatusOK)

	gz := gzip.NewWriter(w)
	if _, err := gz.Write([]byte(completionsBody)); err != nil {
		log.Printf("error writing gzip body: %v", err)
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("error closing gzip writer: %v", err)
	}
}

type conversationRequest struct {
	Items    json.RawMessage `json:"items"`
	Metadata json.RawMessage `json:"metadata"`
}

type embeddingsRequest struct {
	Model      string          `json:"model"`
	Input      json.RawMessage `json:"input"`
	Dimensions int             `json:"dimensions"`
}

func handleEmbeddings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req embeddingsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	var validationErrors []string
	if len(req.Input) == 0 {
		validationErrors = append(validationErrors, "input cannot be empty")
	}
	if req.Model == "" {
		validationErrors = append(validationErrors, "model cannot be empty")
	}
	if len(validationErrors) > 0 {
		http.Error(w, "request validation failed:\n"+strings.Join(validationErrors, "\n"), http.StatusBadRequest)
		return
	}

	if r.URL.Query().Has("error") {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Openai-Version", "2020-10-01")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(errorBody))
		return
	}

	h := w.Header()
	setResponseHeaders(h)
	w.WriteHeader(http.StatusOK)

	gz := gzip.NewWriter(w)
	if _, err := gz.Write([]byte(embeddingsBody)); err != nil {
		log.Printf("error writing gzip body: %v", err)
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("error closing gzip writer: %v", err)
	}
}

func handleConversations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read request body: %v", err), http.StatusBadRequest)
		return
	}

	var req conversationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	var validationErrors []string
	if len(req.Items) == 0 {
		validationErrors = append(validationErrors, "items cannot be empty")
	}
	if len(req.Metadata) == 0 {
		validationErrors = append(validationErrors, "metadata cannot be empty")
	}
	if len(validationErrors) > 0 {
		http.Error(w, "request validation failed:\n"+strings.Join(validationErrors, "\n"), http.StatusBadRequest)
		return
	}

	if r.URL.Query().Has("error") {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Openai-Version", "2020-10-01")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(errorBody))
		return
	}

	h := w.Header()
	setResponseHeaders(h)
	w.WriteHeader(http.StatusOK)

	gz := gzip.NewWriter(w)
	if _, err := gz.Write([]byte(conversationBody)); err != nil {
		log.Printf("error writing gzip body: %v", err)
		return
	}
	if err := gz.Close(); err != nil {
		log.Printf("error closing gzip writer: %v", err)
	}
}

func main() {
	port := os.Getenv("OPENAI_PORT")
	if port == "" {
		port = "8081"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/responses", handleResponses)
	mux.HandleFunc("/v1/chat/completions", handleCompletions)
	mux.HandleFunc("/v1/embeddings", handleEmbeddings)
	mux.HandleFunc("/v1/conversations", handleConversations)

	addr := ":" + port
	log.Printf("mock OpenAI server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
