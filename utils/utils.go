package utils

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

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

/*
	func (s *LanguageScanner) ScanLines(r io.Reader) ([]string, error) {
		out := make([]string, 0)
		scanner := bufio.NewScanner(r)
		for {
			if !scanner.Scan() {
				break
			}
			out = append(out, scanner.Text())
		}

		return out, scanner.Err()
	}

	func (s *LanguageScanner) Score(d []byte) []lingua.ConfidenceValue {
		return s.detector.ComputeLanguageConfidenceValues(string(d))
	}
*/
func (s *LanguageScanner) MaxConfidence(ctx context.Context, lang lingua.Language, scoreCh <-chan string) (string, float64) {
	var (
		out     string
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
			result := s.detector.ComputeLanguageConfidence(toScore, lang)
			log.Printf("score for '%s': %f (%f)", toScore, result, currMax)
			if result > currMax {
				log.Printf("setting out = '%s': %f > %f", toScore, result, currMax)
				currMax = result
				out = toScore
			} else if result == currMax {
				if out < toScore {
					out = toScore
				}
			}
		}
	}
	return out, currMax
}
