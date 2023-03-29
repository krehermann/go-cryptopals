package utils

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/pemistahl/lingua-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHexToBase64(t *testing.T) {
	type args struct {
		hx string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "cryptopals 1.1",
			args: args{
				hx: "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
			},
			want: "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HexToBase64(tt.args.hx)
			if (err != nil) != tt.wantErr {
				t.Errorf("HexToBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("HexToBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func must(t *testing.T, fn func() (any, error)) any {
	v, err := fn()
	require.NoError(t, err)
	return v
}
func TestFixedXor(t *testing.T) {
	type args struct {
		b1 []byte
		b2 []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "len mismatch",
			args: args{
				b1: must(t, func() (any, error) { return hex.DecodeString("00") }).([]byte),
				b2: must(t, func() (any, error) { return hex.DecodeString("0001") }).([]byte),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "00^ 00",
			args: args{
				b1: must(t, func() (any, error) { return hex.DecodeString("00") }).([]byte),
				b2: must(t, func() (any, error) { return hex.DecodeString("00") }).([]byte),
			},
			want:    []byte{0x00},
			wantErr: false,
		},

		{
			name: "00 ^ 01",
			args: args{
				b1: []byte{0x00}, // 00000000
				b2: []byte{0x01}, // 00000001
			},
			want:    []byte{0x01},
			wantErr: false,
		},
		{
			name: "01 ^ 11",
			args: args{
				b1: []byte{0x01}, //  00000001
				b2: []byte{0x03}, //  00000011
			},
			want:    []byte{0x02}, // 00000010
			wantErr: false,
		},
		{
			name: "1c ^ 65",
			args: args{
				b1: []byte{0x1c}, //  00011100
				b2: []byte{0x65}, //  01100101
			},
			want:    []byte{0x79}, // 01111001
			wantErr: false,
		},

		{
			name: "cryptopals 1.2",
			args: args{
				b1: must(t, func() (any, error) { return hex.DecodeString("1c0111001f010100061a024b53535009181c") }).([]byte),
				b2: must(t, func() (any, error) { return hex.DecodeString("686974207468652062756c6c277320657965") }).([]byte),
			},
			want:    must(t, func() (any, error) { return hex.DecodeString("746865206b696420646f6e277420706c6179") }).([]byte),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FixedXor(tt.args.b1, tt.args.b2)
			if (err != nil) != tt.wantErr {
				t.Errorf("FixedXor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FixedXor() = %v, want %v", got, tt.want)
			}
		})
	}
}

type TestTexter struct {
	textToScore string
	key         []byte
}

func (t *TestTexter) Text() string {
	return t.textToScore

}

func (t *TestTexter) Key() []byte {
	return t.key
}
func TestSet1Challenge3(t *testing.T) {
	scoreable := make(chan KeyTexter, 1)

	testMsg, err := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	assert.NoError(t, err)
	generatorFn := func(ch chan<- KeyTexter, maxCodePoint int) {
		defer close(ch)
		for i := 0; i < maxCodePoint; i++ {
			cipher := byte(i)
			decoded := XorCipher(testMsg, cipher)
			ch <- &TestTexter{textToScore: string(decoded), key: []byte{byte(i)}}
		}

	}
	go generatorFn(scoreable, 128)
	ls := NewLanguageScanner()
	result, score := ls.MaxConfidence(context.Background(), lingua.English, scoreable)
	t.Logf("result score %+v %f", result, score)
}

func TestSet1Challenge5(t *testing.T) {
	msg := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	expected, err := hex.DecodeString("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
	assert.NoError(t, err)

	got, err := XorEncrypt([]byte(msg), []byte("ICE"))
	assert.Nil(t, err)
	assert.Equal(t, expected, got)
}

func TestXorRoundtrip(t *testing.T) {
	msg := "a very important message. keep it private and safe. for reals"
	key := "secret"
	t.Logf("msg key len %d, %d", len([]byte(msg)), len([]byte(key)))
	// sanity check. TODO mv
	enc, err := XorEncrypt([]byte(msg), []byte(key))
	require.NoError(t, err)
	t.Logf("enc %s", hex.EncodeToString(enc))
	dec, err := XorEncrypt(enc, []byte(key))
	require.NoError(t, err)
	require.Equal(t, []byte(msg), dec)
}

func TestHammingDistance(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"

	want := 37
	got, err := HammingDistance(s1, s2)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestBlockDistance(t *testing.T) {
	type args struct {
		data   []byte
		keyLen int
		blocks int
	}
	tests := []struct {
		name    string
		args    args
		want    float64
		wantErr bool
	}{
		{
			name: "zero diff l=1",
			args: args{
				data: []byte{0x00, 0x01,
					0x00, 0x01},
				keyLen: 2,
				blocks: 1,
			},
			want: 0,
		},
		{
			name: "zero diff l=2",
			args: args{
				data: []byte{0x00, 0x01, 0x00,
					0x00, 0x01, 0x00,
					0x00, 0x01, 0x00,
					0x00, 0x01, 0x00},
				keyLen: 3,
				blocks: 2,
			},
			want: 0,
		},
		{
			name: "one diff per block, 2 block, k=4",
			args: args{
				data: []byte{0x00, 0x01, 0x00, 0x00,
					0x00, 0x01, 0x00, 0x01,
					0x00, 0x01, 0x00, 0x3,
					0x00, 0x01, 0x00, 0x2},
				keyLen: 4,
				blocks: 2,
			},
			want: (2. / float64(4*2)),
		},

		{
			name: "out of bounds err",
			args: args{
				data: []byte{0x00, 0x01, 0x00, 0x00,
					0x00, 0x01, 0x00, 0x01,
					0x00, 0x01, 0x00, 0x3,
					0x00, 0x01, 0x00, 0x2},
				keyLen: 5,
				blocks: 2,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BlockDistance(tt.args.data, tt.args.keyLen, tt.args.blocks)
			if (err != nil) != tt.wantErr {
				t.Errorf("BlockDistance() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BlockDistance() = %v, want %v", got, tt.want)
			}
		})
	}

	msg := "in this time of fear and confusion, ego and anger, have the courage to accept the unknowable, the inevitiability of faith and the wisdom to choose well"
	key := "the answer"

	enc, err := XorEncrypt([]byte(msg), []byte(key))
	require.NoError(t, err)
	expectedLen := len(key)

	type res struct {
		lngth int
		dist  float64
	}
	results := make([]res, 0)
	for i := 2; i < 2*expectedLen; i++ {
		d, err := BlockDistance(enc, i, 3)
		assert.NoError(t, err)
		results = append(results, res{lngth: i, dist: d})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].dist < results[j].dist
	})

	bestLengths := make([]int, 0)
	for i := 0; i < 5; i++ {
		bestLengths = append(bestLengths, results[i].lngth)
	}
	t.Logf("top 5 lengths %+v", results[:5])

	assert.Contains(t, bestLengths, expectedLen)

}

func TestSet1Challenge8(t *testing.T) {
	f, err := os.Open("testdata/8.txt")
	require.NoError(t, err)

	lines := make([]string, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	err = scanner.Err()
	assert.NoError(t, err)

	var best float64
	bestIdx := 0
	for i, line := range lines {
		enc, err := hex.DecodeString(line)
		require.NoError(t, err)
		score, _ := DetectAES128ECB(enc, 16)
		t.Logf("score %f i %d", score, i)
		if score > best {

			best = score
			bestIdx = i
		}
	}

	t.Logf("best %f idx %d val %s", best, bestIdx, lines[bestIdx])
	assert.Contains(t, lines[bestIdx], "08649af70dc06f4f")
}

func TestPKCS7(t *testing.T) {
	type args struct {
		data  []byte
		padTo int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "set2 challenge1",
			args: args{
				data:  []byte("YELLOW SUBMARINE"),
				padTo: 20,
			},
			want: []byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PKCS7(tt.args.data, tt.args.padTo); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PKCS7() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAES(t *testing.T) {

	k := "this is a key"
	pk := PKCS7([]byte(k), 16)
	d := `Amazing grace! how sweet the sound,
	That saved a wretch; like me!
    I once was lost, but now am found,
	Was blind, but now I see.`

	b := []byte(d)
	src := b[:128]
	t.Run("ecb", func(t *testing.T) {
		a, err := NewAES(pk, AESECB)
		require.NoError(t, err)
		enc, err := a.Encrypt(src)
		require.NoError(t, err)

		got, err := a.Decrypt(enc)
		require.NoError(t, err)
		assert.Equal(t, string(src), string(got))

	})

	t.Run("cbc", func(t *testing.T) {
		a, err := NewAES(pk, AESCBC)
		require.NoError(t, err)
		enc, err := a.Encrypt(src)
		require.NoError(t, err)

		got, err := a.Decrypt(enc)
		require.NoError(t, err)
		assert.Equal(t, string(src), string(got))

	})

	t.Run("set 2 challenge 10", func(t *testing.T) {
		b64, err := os.ReadFile("testdata/10.txt")
		require.NoError(t, err)
		enc, err := base64.RawStdEncoding.DecodeString(string(b64))
		require.NoError(t, err)
		key := "YELLOW SUBMARINE"
		a, err := NewAES([]byte(key), AESCBC)
		require.NoError(t, err)
		txt, err := a.Decrypt(enc)
		assert.NoError(t, err)
		assert.Contains(t, string(txt), "Play that funky music")
	})
}

// set 2 challenge 11
func TestAESOracle_Encrypt(t *testing.T) {

	r := 'X'
	var txt string
	for i := 0; i < 4*16; i++ {
		txt = txt + string(r)
	}

	o := &AESOracle{}
	for i := 0; i < 16; i++ {
		got, err := o.Encrypt([]byte(txt))
		require.NoError(t, err)
		if o.mode == AESECB {
			assert.Equal(t, got[16:32], got[32:48])
		}
	}
}

func TestBreakAESECBOracle(t *testing.T) {
	b4cyphrTxt := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`

	cyphr, err := base64.RawStdEncoding.DecodeString(b4cyphrTxt)
	require.NoError(t, err)

	var maxBlockSize = 32
	t.Run("no prefix", func(t *testing.T) {

		oracle, err := NewAESECBOracle(cyphr, false)
		require.NoError(t, err)

		// determine the block size
		// there are 3 possibilities 16, 24, 32

		prefix := make([]byte, 2*maxBlockSize+1)
		for j := 0; j < len(prefix); j++ {
			prefix[j] = 'A'
		}

		var blockSize int
		for i := 0; i < 3; i++ {
			var l int
			switch i {
			case 0:
				l = 16
			case 1:
				l = 24
			case 2:
				l = 32
			default:
				assert.FailNow(t, "block size search out of range")
			}

			d := prefix[:l]
			d2 := prefix[:l+1]

			enc, err := oracle.Encrypt(d)
			require.NoError(t, err)

			encRunner, err := oracle.Encrypt(d2)
			require.NoError(t, err)

			if bytes.Equal(enc[:l], encRunner[:l]) {
				blockSize = l
				break
			}
		}

		assert.Equal(t, oracle.ciphr.BlockSize(), blockSize)

		// confirm that the encryption is ecb. if we input a
		// slice of len > 2*block  containing the same value, then
		// the first two blocks will be equal under ECB

		enc, err := oracle.Encrypt(prefix)
		require.NoError(t, err)
		assert.True(t, bytes.Equal(enc[:blockSize], enc[blockSize:2*blockSize]))

		// decode a byte a time
		// make a plaintext of length blocksize
		// fix the first blocksize -1
		// for every possible value of the Nth byte, call the oracle with (fixed key + nth byte) and save the first block in a map
		// call the oracle with fixed key, len N-1. compare the returned first block to the map

		result := make([]byte, 0)
		prependedResult := make([]byte, 0)
		for i := 0; i < len(cyphr); i++ {

			block := i / blockSize
			//prepend a static block to result
			prependedResult = append(prependedResult, prefix[:blockSize]...)
			prependedResult = append(prependedResult, result...)

			// the attack prefix is the last blockSize-1 bytes of the prepended result
			attck := prependedResult[len(prependedResult)-(blockSize-1):]
			require.Len(t, attck, blockSize-1)

			solutions, err := generateAttackMap(oracle, attck, block, blockSize)
			require.NoError(t, err)

			// the bytes to send to the oracle input
			// must pad such that our input + the hidden data (in cyphr)
			// aligns so that the byte we are tried to decode
			// is the last byte in a block.
			// since `i` the length of the current result,
			// we what the `ith` byte of the hidden cyphr data
			// to be that last byte in a block

			// padLen is the number of bytes needed to
			// pre-pad the cyphr for it's ith byte to
			// be the last byte in a block
			padLen := (blockSize - 1) - (i % blockSize)
			attackInput := prependedResult[:padLen]
			require.Len(t, attackInput, padLen)
			//hiddenInput := join(attackInput, cyphr)

			got, err := oracle.Encrypt(attackInput)
			require.NoError(t, err)
			result, err = updateResult(result, got, blockSize, solutions)
			require.NoError(t, err, "iter %d", i)

		}
		// we happen to know the ground truth plain text
		want := string(cyphr)
		require.Equal(t, want, string(result))
	})

	t.Run("with prefix", func(t *testing.T) {

		oracle, err := NewAESECBOracle(cyphr, true)
		require.NoError(t, err)

		// determine the block size
		// there are 3 possibilities 16, 24, 32

		prefix := make([]byte, 2*maxBlockSize+1)
		for j := 0; j < len(prefix); j++ {
			prefix[j] = 'A'
		}

		var blockSize int
		for i := 0; i < 3; i++ {
			var l int
			switch i {
			case 0:
				l = 16
			case 1:
				l = 24
			case 2:
				l = 32
			default:
				assert.FailNow(t, "block size search out of range")
			}

			d := prefix[:2*l]
			//			d2 := prefix[:2*l+1]

			enc, err := oracle.Encrypt(d)
			require.NoError(t, err)

			_, r := DetectAES128ECB(enc, l)
			if len(r) != 0 {
				blockSize = l

				t.Logf("detected ECB %+v", r)
				break
			}
			/*
				encRunner, err := oracle.Encrypt(d2)
				require.NoError(t, err)

				if bytes.Equal(enc[:l], encRunner[:l]) {
					blockSize = l
					break
				}
			*/
		}

		require.Equal(t, oracle.ciphr.BlockSize(), blockSize)

		return
		// confirm that the encryption is ecb. if we input a
		// slice of len > 2*block  containing the same value, then
		// the first two blocks will be equal under ECB

		enc, err := oracle.Encrypt(prefix)
		require.NoError(t, err)

		require.True(t, bytes.Equal(enc[:blockSize], enc[blockSize:2*blockSize]))

		// decode a byte a time
		// make a plaintext of length blocksize
		// fix the first blocksize -1
		// for every possible value of the Nth byte, call the oracle with (fixed key + nth byte) and save the first block in a map
		// call the oracle with fixed key, len N-1. compare the returned first block to the map

		result := make([]byte, 0)
		prependedResult := make([]byte, 0)
		for i := 0; i < len(cyphr); i++ {

			block := i / blockSize
			//prepend a static block to result
			prependedResult = append(prependedResult, prefix[:blockSize]...)
			prependedResult = append(prependedResult, result...)

			// the attack prefix is the last blockSize-1 bytes of the prepended result
			attck := prependedResult[len(prependedResult)-(blockSize-1):]
			require.Len(t, attck, blockSize-1)

			solutions, err := generateAttackMap(oracle, attck, block, blockSize)
			require.NoError(t, err)

			// the bytes to send to the oracle input
			// must pad such that our input + the hidden data (in cyphr)
			// aligns so that the byte we are tried to decode
			// is the last byte in a block.
			// since `i` the length of the current result,
			// we what the `ith` byte of the hidden cyphr data
			// to be that last byte in a block

			// padLen is the number of bytes needed to
			// pre-pad the cyphr for it's ith byte to
			// be the last byte in a block
			padLen := (blockSize - 1) - (i % blockSize)
			attackInput := prependedResult[:padLen]
			require.Len(t, attackInput, padLen)
			//hiddenInput := join(attackInput, cyphr)

			got, err := oracle.Encrypt(attackInput)
			require.NoError(t, err)
			result, err = updateResult(result, got, blockSize, solutions)
			require.NoError(t, err, "iter %d", i)

		}
		// we happen to know the ground truth plain text
		want := string(cyphr)
		require.Equal(t, want, string(result))
	})

}

func generateAttackMap(oracle *AESECBOracle, attackBuf []byte, block, blockSize int) (map[string]byte, error) {

	temp := make([]byte, len(attackBuf)+1)
	copy(temp, attackBuf)

	attackPos := len(temp) - 1
	solutionMap := make(map[string]byte)
	for i := 0; i <= 128; i++ {
		val := byte(i)
		temp[attackPos] = val
		res, err := oracle.Encrypt(temp)

		if err != nil {
			return nil, err
		}
		res = res[:blockSize]
		solutionMap[hex.EncodeToString(res)] = val
	}
	return solutionMap, nil
}

func updateResult(currentResult, cyphr []byte, blockSize int, solutionMap map[string]byte) ([]byte, error) {
	block := len(currentResult) / blockSize
	attackResult := cyphr[block*blockSize : (block+1)*blockSize]

	s := hex.EncodeToString(attackResult)
	decodeByte, exists := solutionMap[s]
	if !exists {
		return nil, fmt.Errorf("attack result %s not in solution map", s)
	}
	x := make([]byte, 0)
	x = append(x, currentResult...)
	x = append(x, decodeByte)
	return x, nil
}

func TestDetectAES128ECB(t *testing.T) {
	maxBlockSize := 32

	intervalStart := maxBlockSize
	intervalEnd := 3 * maxBlockSize
	l := intervalEnd - intervalStart
	d := make([]byte, 32*5)
	for i := range d {
		if i < 32 || i > 3*32 {
			d[i] = byte(i)
		} else {
			d[i] = 'a'
		}
	}

	type args struct {
		data      []byte
		blockSize int
	}
	tests := []struct {
		name  string
		args  args
		want  float64
		want1 map[string][]int
	}{
		{
			name: "16",
			args: args{
				data:      d,
				blockSize: 16,
			},
			want: float64(l) / 16,
			want1: map[string][]int{
				hex.EncodeToString(d[intervalStart : intervalStart+16]): []int{2, 3, 4, 5},
			},
		},
		{
			name: "32",
			args: args{
				data:      d,
				blockSize: 32,
			},
			want: float64(l) / 32,
			want1: map[string][]int{
				hex.EncodeToString(d[intervalStart : intervalStart+32]): []int{1, 2},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := DetectAES128ECB(tt.args.data, tt.args.blockSize)
			if got != tt.want {
				t.Errorf("DetectAES128ECB() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("DetectAES128ECB() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
