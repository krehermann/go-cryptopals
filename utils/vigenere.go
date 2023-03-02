package utils

import "errors"

type Vigenere struct {
	data []byte
}

var KeyLengthTooLarge = errors.New("key length to large")

type KeyCandidate struct {
	Length int
	Score  float64
}

func (v *Vigenere) RankKeyLengths(min, max int) ([]KeyCandidate, error) {
	out := make([]KeyCandidate, 0)
	for i := min; i < max; i++ {
		s, err := BlockDistance(v.data, i, 2)
		if err != nil {
			return out, err
		}
		out = append(out, KeyCandidate{Length: i, Score: s})
	}
	return out, nil
}

func (v *Vigenere) chunk(n int) [][]byte {
	chunks := make([][]byte, 0)

	start := 0
	for {
		end := (start + 1) * n
		if end > len(v.data) {
			break
		}
		chunks = append(chunks, v.data[start:end])
	}
	return chunks
}

func (v *Vigenere) transpose(chunks [][]byte) [][]byte {

	transpose := make([][]byte, len(chunks[0]))
	for i, chunk := range chunks {
		for j := range chunk {
			if len(transpose[j]) == 0 {
				transpose[j] = make([]byte, len(chunks))
			}
			transpose[j][i] = chunks[i][j]
		}
	}

}
