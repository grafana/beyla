// Package persistence contains functions needed to serialize
// and deserialize the model data.
package persistence

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/AlessandroPomponio/go-gibberish/structs"
)

// WriteKnowledgeBase writes the gibberish data model to disk.
func WriteKnowledgeBase(data *structs.GibberishData, outputFileName string) error {

	toWrite, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("WriteKnowledgeBase: unable to marshal training data: %s", err)
	}

	err = ioutil.WriteFile(outputFileName, toWrite, 0644)
	if err != nil {
		return fmt.Errorf("WriteKnowledgeBase: unable to save knowledge file on disk: %s", err)
	}

	return nil

}

// LoadKnowledgeBase loads the gibberish data model from disk.
func LoadKnowledgeBase(fileName string) (*structs.GibberishData, error) {

	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("LoadKnowledgeBase: unable to open knowledge base: %s", err)
	}

	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("LoadKnowledgeBase: unable to read knowledge base content: %s", err)
	}

	var data structs.GibberishData
	err = json.Unmarshal(content, &data)
	if err != nil {
		return nil, fmt.Errorf("LoadKnowledgeBase: unable to unmarshal knowledge base content: %s", err)
	}

	return &data, nil

}
