package utils

import "strings"

var (
	lower []rune = []rune{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	}
	punc []rune = []rune{',', ' ', '.', '\''}

	upper          []rune
	alphabet       []rune
	alphabetScreen map[rune]struct{}
	// http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
	freq = map[rune]float64{
		'A': 8.55,
		'B': 1.60,
		'C': 3.16,
		'D': 3.87,
		'E': 12.10,
		'F': 2.18,
		'G': 2.09,
		'H': 4.96,
		'I': 7.33,
		'J': 0.22,
		'K': 0.81,
		'L': 4.21,
		'M': 2.53,
		'N': 7.17,
		'O': 7.47,
		'P': 2.07,
		'Q': 0.10,
		'R': 6.33,
		'S': 6.73,
		'T': 8.94,
		'U': 2.68,
		'V': 1.06,
		'W': 1.83,
		'X': 0.19,
		'Y': 1.72,
		'Z': 0.11,
	}
)

func init() {
	upper = make([]rune, 0, len(lower))
	for _, l := range lower {
		upper = append(upper, []rune(strings.ToUpper(string(l)))...)
	}
	alphabet = append(alphabet, lower...)
	alphabet = append(alphabet, upper...)
	alphabet = append(alphabet, punc...)
	alphabetScreen = make(map[rune]struct{})
	for _, r := range alphabet {
		alphabetScreen[r] = struct{}{}
	}
}

func SimpleEnglishScore(s string) float64 {
	hits := 0
	for _, r := range s {
		if _, ok := alphabetScreen[r]; ok {
			hits += 1
		}
	}
	// scale is number of runes in the alphabet
	scale := float64(hits) / float64(len(s))
	//return scale
	cs := strings.ToUpper(s)
	// weight is sum of letter probabilities
	weight := float64(0)
	for _, r := range cs {
		val, ok := freq[r]
		if ok {
			weight += val
		}
	}

	return scale * weight
}
