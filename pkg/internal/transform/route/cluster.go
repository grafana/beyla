package route

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AlessandroPomponio/go-gibberish/gibberish"
	"github.com/AlessandroPomponio/go-gibberish/structs"
)

var classifier *structs.GibberishData

const maxSegments = 10
const maxPartSize = 25

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

func ClusterPath(path string) string {
	if path == "" {
		return path
	}

	pArr := []byte(path)
	var sb strings.Builder

	tmp := make([]byte, maxPartSize)
	tmpPos := 0
	skip := false
	nSegments := 0
	for _, c := range pArr {
		if c == '/' {
			nSegments++
			if skip {
				sb.WriteByte('*')
			} else {
				if tmpPos > 0 {
					segmentOrAsterisk(tmp[:tmpPos], &sb)
				}
			}

			if nSegments >= maxSegments {
				break
			}

			sb.WriteByte('/')
			skip = false
			tmpPos = 0
		} else if !skip {
			tmp[tmpPos] = c
			tmpPos++
			if tmpPos >= maxPartSize {
				skip = true
			}
			if !isAlpha(c) {
				skip = true
			}

		}
	}

	if skip {
		sb.WriteByte('*')
	} else {
		segmentOrAsterisk(tmp[:tmpPos], &sb)
	}

	return sb.String()
}

func segmentOrAsterisk(tmp []byte, sb *strings.Builder) {
	if len(tmp) > 0 {
		if !gibberish.IsGibberish(string(tmp), classifier) {
			sb.Write(tmp)
		} else {
			sb.WriteByte('*')
		}
	}
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_'
}
