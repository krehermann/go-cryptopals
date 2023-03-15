package utils

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
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

type AES struct {
	ciphr cipher.Block
	mode  AESMode
	// optional
	cbcIV []byte
}

type AESOpt func(*AES)

func WithIV(iv []byte) AESOpt {
	return func(a *AES) {
		a.cbcIV = iv
	}
}

func NewAES(key []byte, mode AESMode, opts ...AESOpt) (*AES, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	a := &AES{
		ciphr: c,
		mode:  mode,
		cbcIV: make([]byte, len(key)),
	}

	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

func (a *AES) Encrypt(src []byte) ([]byte, error) {
	result := make([]byte, len(src))
	blockSize := a.ciphr.BlockSize()

	switch a.mode {
	case AESECB:
		for start, end := 0, blockSize; end <= len(src); start, end = start+blockSize, end+blockSize {
			a.ciphr.Encrypt(result[start:end], src[start:end])
		}
	case AESCBC:
		prevBlock := a.cbcIV
		for start, end := 0, blockSize; end <= len(src); start, end = start+blockSize, end+blockSize {
			transformed, err := FixedXor(prevBlock, src[start:end])
			if err != nil {
				return nil, err
			}
			a.ciphr.Encrypt(result[start:end], transformed)
			prevBlock = result[start:end]
		}
	}
	return result, nil

}

func (a *AES) Decrypt(src []byte) ([]byte, error) {
	result := make([]byte, len(src))
	blockSize := a.ciphr.BlockSize()

	switch a.mode {
	case AESECB:
		for start, end := 0, blockSize; end <= len(src); start, end = start+blockSize, end+blockSize {
			a.ciphr.Decrypt(result[start:end], src[start:end])
		}
	case AESCBC:
		prevBlock := a.cbcIV
		tmp := make([]byte, a.ciphr.BlockSize())

		for start, end := 0, blockSize; end <= len(src); start, end = start+blockSize, end+blockSize {
			a.ciphr.Decrypt(tmp, src[start:end])

			transformed, err := FixedXor(prevBlock, tmp)
			if err != nil {
				return nil, err
			}
			copy(result[start:end], transformed)
			prevBlock = src[start:end]
		}
	}

	return result, nil
}

type AESMode int

type AESOracle struct {
	mode AESMode
}

func (o *AESOracle) prepareForOracle(txt []byte) ([]byte, error) {
	d := make([]byte, 0)

	prefix, err := generateBytes(5, 10)
	if err != nil {
		return nil, err
	}
	d = append(d, prefix...)
	d = append(d, txt...)

	suffix, err := generateBytes(5, 10)
	if err != nil {
		return nil, err
	}

	d = append(d, suffix...)
	return d, nil
}

func (o *AESOracle) Encrypt(txt []byte) ([]byte, error) {

	d, err := o.prepareForOracle(txt)
	if err != nil {
		return nil, err
	}
	v, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return nil, err
	}
	m := AESMode(v.Int64())
	log.Printf("mode %d", m)

	k := make([]byte, 16)
	n, err := rand.Read(k)
	if err != nil {
		return nil, err
	}
	if n != 16 {
		return nil, fmt.Errorf("error generating 16 byte key, got %d", n)
	}
	a, err := NewAES(k, m)
	if err != nil {
		return nil, err
	}
	o.mode = m
	return a.Encrypt(d)

}

type ConsistentAESECB struct {
	*AES
}

func NewConsistentAESECB() (*ConsistentAESECB, error) {
	r, err := rand.Int(rand.Reader, big.NewInt(3))
	if err != nil {
		return nil, err
	}
	var blockSize int
	switch r.Int64() {
	case 0:
		blockSize = 16
	case 1:
		blockSize = 24
	case 2:
		blockSize = 32
	default:
		return nil, fmt.Errorf("error generating block size. unexpected enum value %d", r.Int64())
	}

	key := make([]byte, blockSize)
	n, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("error generating key %w", err)
	}
	if n != blockSize {
		return nil, fmt.Errorf("bad key len generated. want %d got %d", blockSize, n)
	}

	a, err := NewAES(key, AESECB)
	if err != nil {
		return nil, err
	}
	return &ConsistentAESECB{
		AES: a,
	}, nil
}

func generateBytes(min, max int64) ([]byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(min+1))
	if err != nil {
		return nil, fmt.Errorf("generateing n prefix: %w", err)
	}

	wantN := n.Int64() + (max - min)
	buf := make([]byte, wantN)

	got, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}
	if got != int(wantN) {
		return nil, fmt.Errorf("error generating random byte prefix, want %d got %d", wantN, got)
	}

	return buf, nil

}

const (
	AESECB AESMode = iota
	AESCBC
)

func DetectAES128ECB(data []byte) float64 {
	var score float64
	chunks := chunk(data, 16)
	for i, chnk := range chunks {
		for j := i + 1; j < len(chunks); j++ {
			if bytes.Equal(chunks[j], chnk) {
				score += 1
			}
		}
	}
	return score
}

func PKCS7(data []byte, padTo int) []byte {
	if len(data) >= padTo {
		return data[:padTo]
	}
	l := len(data)
	d := padTo - l
	out := make([]byte, 0, padTo)
	out = append(out, data...)

	for i := 0; i < d; i++ {
		out = append(out, byte(d))
	}
	return out
}
