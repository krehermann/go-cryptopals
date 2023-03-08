package utils

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
)

type Vigenere struct {
	candidates int
	minKeyLen  int
	maxKeyLen  int
}

var KeyLengthTooLarge = errors.New("key length to large")

type KeyCandidate struct {
	Length int
	Score  float64
	val    []byte
}

func RankKeyLengths(data []byte, min, max int) ([]*KeyCandidate, error) {
	out := make([]*KeyCandidate, 0)
	for i := min; i < max; i++ {
		s, err := BlockDistance(data, i, 2)
		if err != nil {
			return out, err
		}
		out = append(out, &KeyCandidate{Length: i, Score: s, val: make([]byte, i)})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Score > out[j].Score
	})
	return out, nil
}

func chunk(data []byte, n int) [][]byte {
	chunks := make([][]byte, 0)
	start := 0
	for {
		end := start + n
		if end > len(data) {
			break
		}
		chunks = append(chunks, data[start:end])
		start = end
	}
	return chunks
}

func (v *Vigenere) Decrypt(data []byte) (Result, error) {
	keys, err := RankKeyLengths(data, v.minKeyLen, v.maxKeyLen)
	if err != nil {
		return Result{}, err
	}
	keys = keys[:v.candidates]
	for _, key := range keys {
		key.findBest(data)
		log.Printf("got val %s", key.val)
	}
	// score full decryption against all accumulated keys
	ls := NewLanguageScanner()
	scoreCh := make(chan KeyTexter, len(keys))
	for _, key := range keys {
		d, err := XorEncrypt(data, key.val)
		if err != nil {
			return Result{}, err
		}
		log.Printf("candidate key %+v %s", key, string(d[:20]))
		c := &vigenereCandidate{
			key:           key.val,
			decryptedData: d,
		}
		scoreCh <- c
	}
	close(scoreCh)
	best, _ := ls.SimpleEnglishMax(context.Background(), scoreCh) //ls.MaxConfidence(context.Background(), lingua.English, scoreCh)
	//gross...
	vc := best.(*vigenereCandidate)
	return Result{
		Output: best.Text(),
		Key:    vc.key,
	}, nil
}

func (key *KeyCandidate) findBest(data []byte) {

	log.Printf("testing key %+v", key)
	chunks := chunk(data, key.Length)
	tBlocks := transpose(chunks)
	if key.Length != len(tBlocks) {
		err := fmt.Errorf("key and block length don't match %d %d %+v %+v", key.Length, len(tBlocks), key, tBlocks)
		panic(err)
	}

	// start accumulator
	for bIdx, b := range tBlocks {
		// score each block
		ls := NewLanguageScanner()
		scoreCh := make(chan KeyTexter, 1)
		go func(chan KeyTexter) {
			defer close(scoreCh)
			// send best to accumulator
			for i := 0; i < 128; i++ {
				k := byte(i)
				d := XorCipher(b, k)
				c := &blockKeyCandidate{
					key:           k,
					blockIndex:    bIdx,
					decryptedData: d,
				}
				scoreCh <- c
			}
		}(scoreCh)
		best, _ := ls.SimpleEnglishMax(context.Background(), scoreCh)
		//gross...
		vc := best.(*blockKeyCandidate)
		log.Printf("idx %d val %s %v", vc.blockIndex, string(vc.key), vc.key)
		key.val[vc.blockIndex] = vc.key
	}
	log.Println("key val", string(key.val))
	// wait for accumulator; create cipher key
}

type blockKeyCandidate struct {
	key           byte
	blockIndex    int
	decryptedData []byte
}

func (vc *blockKeyCandidate) Text() string {
	return string(vc.decryptedData)
}

func (vc *blockKeyCandidate) Key() []byte {
	return []byte{vc.key}
}

type vigenereCandidate struct {
	key           []byte
	decryptedData []byte
}

func (vc *vigenereCandidate) Text() string {
	return string(vc.decryptedData)
}

func (vc *vigenereCandidate) Key() []byte {
	return vc.key
}

type Result struct {
	Output string
	Key    []byte
}

func transpose(chunks [][]byte) [][]byte {

	transpose := make([][]byte, len(chunks[0]))
	log.Printf("transpose %d %d", len(chunks), len(chunks[0]))
	for i, chunk := range chunks {
		for j := range chunk {
			if len(transpose[j]) == 0 {
				transpose[j] = make([]byte, len(chunks))
			}
			transpose[j][i] = chunks[i][j]
		}
	}

	return transpose
}
