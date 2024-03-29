package utils

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/bits"
	"strings"

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
	blockSize := a.ciphr.BlockSize()
	padLen := len(src) % blockSize
	if padLen != 0 {
		padLen = blockSize - padLen
	}
	src = PKCS7(src, len(src)+padLen)
	result := make([]byte, len(src))

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

	// drop padding
	return truncatePKCS7(result)

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

func appendIfNotExists(appendable []int, toAppend ...int) []int {
	out := appendable
	for _, x := range toAppend {
		exists := false
		for _, val := range appendable {
			if x == val {
				exists = true
				break
			}
		}
		if !exists {
			out = append(out, x)
		}
	}
	return out
}

func DetectAES128ECB(data []byte, blockSize int) (float64, map[string][]int) {
	var score int
	matchingOffsets := make(map[string][]int)
	chunks := chunk(data, blockSize)
	for i, chnk := range chunks {
		for j := i + 1; j < len(chunks); j++ {
			if bytes.Equal(chunks[j], chnk) {
				s := hex.EncodeToString(chnk)
				mtchIdxs, exists := matchingOffsets[s]
				if !exists {
					mtchIdxs = make([]int, 0)
				}
				l := len(mtchIdxs)
				mtchIdxs = appendIfNotExists(mtchIdxs, i, j)
				score += len(mtchIdxs) - l
				matchingOffsets[s] = mtchIdxs
			}
		}
	}

	return float64(score), matchingOffsets
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

var ErrInvalidPKCS7 = errors.New("invalid PKCS7 padding")

func truncatePKCS7(data []byte) ([]byte, error) {
	// read last byte
	x := data[len(data)-1]
	v := int(x)

	expected := make([]byte, v)
	for i := 0; i < v; i++ {
		expected[i] = byte(v)
	}

	if bytes.Equal(data[len(data)-v:], expected) {
		return data[:len(data)-v], nil
	}

	return data, ErrInvalidPKCS7
}

type AESECBOracle struct {
	usePrefix bool
	prefix    []byte
	hidden    []byte
	*ConsistentAESECB
}

func NewAESECBOracle(hidden []byte, usePrefix bool) (*AESECBOracle, error) {
	randPrefix := make([]byte, 0)
	if usePrefix {
		r, err := rand.Int(rand.Reader, big.NewInt(128))
		if err != nil {
			return nil, err
		}
		randPrefix = make([]byte, r.Int64())
		n, err := rand.Read(randPrefix)
		if err != nil {
			return nil, err
		}
		if n != int(r.Int64()) {
			return nil, fmt.Errorf("random prefix not expected len( %d != %d)", n, r.Int64())
		}
	}

	cAes, err := NewConsistentAESECB()
	if err != nil {
		return nil, err
	}
	return &AESECBOracle{
		usePrefix:        usePrefix,
		prefix:           randPrefix,
		hidden:           hidden,
		ConsistentAESECB: cAes,
	}, nil
}

func (o *AESECBOracle) Encrypt(txt []byte) ([]byte, error) {
	d := make([]byte, 0)
	if o.usePrefix {
		d = o.prefix
	}

	d = append(d, txt...)
	d = append(d, o.hidden...)
	return o.ConsistentAESECB.Encrypt(d)
}

type orderedKey struct {
	position int
	V        string
}

type CookieParser struct {
	m map[string]orderedKey
}

func (c *CookieParser) Parse(cookie string) error {
	if c.m == nil {
		c.m = map[string]orderedKey{}
	}
	pairs := strings.Split(cookie, "&")
	for i, pair := range pairs {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			return fmt.Errorf("bad input %s at %s", cookie, pair)
		}
		c.m[parts[0]] = orderedKey{
			position: i,
			V:        parts[1]}
	}
	return nil
}

func (c *CookieParser) encode() string {
	tempKV := make([]string, len(c.m))

	for k, v := range c.m {
		tempKV[v.position] = fmt.Sprintf("%s=%s", k, v.V)
	}
	return strings.Join(tempKV, "&")
}

type cookie struct {
	email string
	uid   int
	role  string
}

func (c *cookie) encode() string {
	var result string

	result = fmt.Sprintf("email=%s", eatRunes(c.email))
	result = fmt.Sprintf("%s&uid=%d", result, c.uid)
	result = fmt.Sprintf("%s&role=%s", result, c.role)
	return result

}

func eatRunes(s string) string {
	var result string
	for _, r := range s {
		if r == '&' || r == '=' {
			continue
		} else {
			result = result + string(r)
		}
	}
	return result
}

func profileFor(email string) string {
	/*
		p := &CookieParser{}

		p.Parse(eatRunes(email))

		return p.encode()
	*/
	var result string

	result = fmt.Sprintf("email=%s", eatRunes(email))
	result = fmt.Sprintf("%s&uid=%d", result, 7)
	result = fmt.Sprintf("%s&role=%s", result, "user")
	return result
}
