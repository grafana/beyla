package route

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/AlessandroPomponio/go-gibberish/gibberish"
	"github.com/AlessandroPomponio/go-gibberish/structs"
	lru "github.com/hashicorp/golang-lru/v2"
)

var classifier *structs.GibberishData

const maxSegments = 10

var words, _ = lru.New[string, bool](8192)

//go:embed classifier.json
var dataFile embed.FS

func loadKnowledgeBase() (*structs.GibberishData, error) {
	content, err := dataFile.ReadFile("classifier.json")
	if err != nil {
		return nil, fmt.Errorf("LoadKnowledgeBase: unable to read knowledge base content: %w", err)
	}

	var data structs.GibberishData
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, fmt.Errorf("LoadKnowledgeBase: unable to unmarshal knowledge base content: %w", err)
	}

	return &data, nil
}

func InitAutoClassifier() error {
	var err error
	classifier, err = loadKnowledgeBase()
	if err != nil {
		return err
	}

	return nil
}

//nolint:cyclop
func ClusterPath(path string, replacement byte) string {
	if path == "" {
		return path
	}

	p := []byte(path)
	sPos := 0
	sFwd := 0

	skip := false
	skipGrace := true
	nSegments := 0
	for _, c := range p {
		if c == '/' {
			nSegments++
			if skip {
				p[sPos] = replacement
				sPos++
			} else if sFwd > sPos {
				if !okWord(string(p[sPos:sFwd])) {
					p[sPos] = replacement
					sPos++
				} else {
					sPos = sFwd
				}
			}

			if nSegments >= maxSegments {
				break
			}

			p[sPos] = '/'
			sPos++
			sFwd = sPos
			skip = false
			skipGrace = true
		} else if !skip {
			p[sFwd] = c
			sFwd++
			if !isAlpha(c) {
				if skipGrace && (sFwd-sPos) == 2 {
					skipGrace = false
					continue
				}
				skip = true
			}
		}
	}

	if skip {
		p[sPos] = replacement
		sPos++
	} else if sFwd > sPos {
		if !okWord(string(p[sPos:sFwd])) {
			p[sPos] = replacement
			sPos++
		} else {
			sPos = sFwd
		}
	}

	return string(p[:sPos])
}

func okWord(w string) bool {
	_, ok := words.Get(w)
	if ok {
		return ok
	}
	if gibberish.IsGibberish(w, classifier) {
		return false
	}

	words.Add(w, true)
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == '.'
}
