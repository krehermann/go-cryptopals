package utils

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"math/bits"

	"github.com/pemistahl/lingua-go"
)

func HexToBase64(hx string) (string, error) {
	b, err := hex.DecodeString(hx)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func FixedXor(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return nil, fmt.Errorf("buffers must be the same length (%d, %d)", len(b1), len(b2))
	}

	out := make([]byte, len(b1))
	for i := 0; i < len(out); i++ {
		out[i] = b1[i] ^ b2[i]
	}
	return out, nil
}

func XorCipher(msg []byte, cipher byte) []byte {
	out := make([]byte, len(msg))
	for i := 0; i < len(out); i++ {
		out[i] = msg[i] ^ cipher
	}
	return out
}

type LanguageScanner struct {
	detector lingua.LanguageDetector
}

func NewLanguageScanner() *LanguageScanner {
	detector := lingua.NewLanguageDetectorBuilder().FromAllLanguages().Build()
	return &LanguageScanner{
		detector: detector,
	}
}

type Texter interface {
	Text() string
}

type Keyer interface {
	Key() []byte
}

type KeyTexter interface {
	Texter
	Keyer
}

func (s *LanguageScanner) MaxConfidence(ctx context.Context, lang lingua.Language, scoreCh <-chan KeyTexter) (KeyTexter, float64) {
	scoreFn := func(t Texter) float64 { return s.detector.ComputeLanguageConfidence(t.Text(), lang) }
	return s.max(ctx, scoreFn, scoreCh)
}

func (s *LanguageScanner) max(ctx context.Context, scoreFn func(t Texter) float64, scoreCh <-chan KeyTexter) (KeyTexter, float64) {
	var (
		out     KeyTexter
		currMax float64
	)
PROCESS:
	for {
		select {
		case <-ctx.Done():
			break PROCESS
		case toScore, ok := <-scoreCh:
			if !ok {
				break PROCESS
			}
			result := scoreFn(toScore)
			//			log.Printf("score for '%s', '%s': %f (%f)", toScore.Text(), toScore.Key(), result, currMax)
			if result > currMax {
				//				log.Printf("setting out = '%s', '%s': %f > %f", toScore.Text(), toScore.Key(), result, currMax)
				currMax = result
				out = toScore
			}
		}
	}
	return out, currMax
}

func (s *LanguageScanner) SimpleEnglishMax(ctx context.Context, scoreCh <-chan KeyTexter) (KeyTexter, float64) {
	scoreFn := func(t Texter) float64 { return SimpleEnglishScore(t.Text()) }
	return s.max(ctx, scoreFn, scoreCh)
}

func XorEncrypt(msg, key []byte) ([]byte, error) {
	fixedKey := make([]byte, len(msg))
	for i := 0; i < len(fixedKey); i += 1 {
		fixedKey[i] = key[i%len(key)]
	}
	return FixedXor(msg, fixedKey)
}

func HammingDistance(s1, s2 string) (int, error) {
	b1, b2 := padToMatchingLen(s1, s2)
	xor, err := FixedXor(b1, b2)
	if err != nil {
		return 0, err
	}
	cnt := 0
	for _, b := range xor {
		cnt += bits.OnesCount8(uint8(b))
	}
	return cnt, nil
}

func padToMatchingLen(s1, s2 string) ([]byte, []byte) {
	max := int(math.Max(float64(len(s1)), float64(len(s2))))

	b1 := []byte(s1)
	b2 := []byte(s2)
	return mustPad(b1, max), mustPad(b2, max)
}

func pad(b []byte, l int) ([]byte, error) {
	if len(b) == l {
		return b, nil
	}
	if len(b) > l {
		return nil, fmt.Errorf("pad: input to large")
	}
	tmp := make([]byte, l)
	copy(tmp, b)
	return tmp, nil
}

func mustPad(b []byte, l int) []byte {
	out, err := pad(b, l)
	if err != nil {
		panic(err)
	}
	return out
}

func BlockDistance(data []byte, keyLen int, blocks int) (float64, error) {
	if 2*blocks*keyLen > len(data) {
		return 0, fmt.Errorf("out of range. data length less than 2*block*keylen (%d< %d)", len(data), 2*blocks*keyLen)
	}

	var sum int
	for i := 0; i < 2*blocks; i += 2 {
		s1 := string(data[i*keyLen : (i+1)*keyLen])
		s2 := string(data[(i+1)*keyLen : (i+2)*keyLen])
		dist, err := HammingDistance(s1, s2)
		if err != nil {
			return 0, err
		}
		sum += dist
	}

	return float64(sum) / (float64(blocks) * float64(keyLen)), nil
}

func AES128ECB(data []byte, key [16]byte) ([]byte, error) {
	blockSize := 16 // 16 bytes, 128 bits
	ciphr, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	plainText := make([]byte, len(data))
	for start, end := 0, blockSize; end < len(data); start, end = start+blockSize, end+blockSize {
		ciphr.Decrypt(plainText[start:end], data[start:end])
	}
	return plainText, nil
}

func DetectAES128ECB(data []byte) float64 {
	lens := []int{2, 3, 5, 7, 8}
	chunks := chunk(data, 16)

	var score float64
	// for each length, take a chunk, find all continugous bytes of give length
	// scan all chunks for overlap an
	for _, l := range lens {
		for i := range chunks {
			ngrams := getAllNgrams(chunks[i], l)
			for _, ngram := range ngrams {
				for j := i; j < len(chunks); j++ {
					score += scoreOverlap(chunks[j], ngram)
				}
			}
		}
	}
	return score
}

func getAllNgrams(chunk []byte, n int) [][]byte {
	out := make([][]byte, 0)
	for i := 0; i+n < len(chunk); i++ {
		ngram := chunk[i : n+i]
		out = append(out, ngram)
	}
	return out
}

func scoreOverlap(chunk []byte, pattern []byte) float64 {
	n := len(pattern)
	matches := 0
	for i := 0; i+n < len(chunk); i++ {
		ngram := chunk[i : n+i]
		if bytes.Compare(pattern, ngram) == 0 {
			matches += 1
		}
	}
	// normalize to the largest number of non-overlapping mathces possible
	// for given lenght of pattern and chunck. eg len 2 pattern and 16 chunk => max of 8
	max := float64(len(chunk)) / float64(len(pattern))
	return float64(matches) / max

}
