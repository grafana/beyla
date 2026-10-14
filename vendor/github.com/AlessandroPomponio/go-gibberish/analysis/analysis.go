// Package analysis contains the functions needed to
// analyze lines.
package analysis

import (
	"fmt"
	"math"
	"strings"

	"github.com/AlessandroPomponio/go-gibberish/consts"
	"github.com/AlessandroPomponio/go-gibberish/structs"
)

// AverageTransitionProbability returns the probability of
// generating the input string digraph by digraph according
// to the occurrences matrix.
func AverageTransitionProbability(line string, occurrences [][]float64, position map[rune]int) (float64, error) {

	logProb := 0.0
	transitionCt := 0.0

	for _, pair := range GetDigraphs(line) {

		firstPosition, firstRuneFound := position[pair.First]
		if !firstRuneFound {
			return -1, fmt.Errorf("AverageTransitionProbability: unable to find the position of the rune %s", string(pair.First))
		}

		secondPosition, secondRuneFound := position[pair.Second]
		if !secondRuneFound {
			return -1, fmt.Errorf("AverageTransitionProbability: unable to find the position of the rune %s", string(pair.First))
		}

		logProb += occurrences[firstPosition][secondPosition]
		transitionCt++

	}

	if transitionCt == 0 {
		transitionCt = 1
	}

	return math.Exp(logProb / transitionCt), nil

}

// GetDigraphs returns pairs of adjacent runes, after
// normalizing the input line.
func GetDigraphs(line string) []structs.Digraph {

	runes := Normalize(line)
	if len(runes) == 0 {
		return []structs.Digraph{}
	}

	digraphs := make([]structs.Digraph, len(runes)-1)
	for i := 0; i < len(runes)-1; i++ {
		digraphs[i] = structs.Digraph{First: runes[i], Second: runes[i+1]}
	}

	return digraphs

}

// Normalize returns the subset of runes in the line
// that are in the accepted characters. This helps
// keeping the  model relatively small by ignoring
// punctuation, symbols, etc.
func Normalize(line string) []rune {

	line = strings.ToLower(line)
	result := make([]rune, 0, len(line))

	for _, r := range line {

		if strings.ContainsRune(consts.AcceptedCharacters, r) {
			result = append(result, r)
		}

	}

	return result

}

// MaxForSlice returns the maximum value in a
// float64 slice.
func MaxForSlice(slice []float64) float64 {

	max := -math.MaxFloat64
	for _, item := range slice {

		if item > max {
			max = item
		}

	}

	return max

}

// MinForSlice returns the minimum value in
// a float64 slice.
func MinForSlice(slice []float64) float64 {

	min := math.MaxFloat64
	for _, item := range slice {

		if item < min {
			min = item
		}

	}

	return min

}
