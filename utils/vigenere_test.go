package utils

import (
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_transpose(t *testing.T) {
	type args struct {
		chunks [][]byte
	}
	tests := []struct {
		name string
		args args
		want [][]byte
	}{
		{
			name: "2x3",
			args: args{
				chunks: [][]byte{
					{0x00, 0x01, 0x02},
					{0x10, 0x11, 0x12},
				},
			},
			want: [][]byte{
				{0x00, 0x10},
				{0x01, 0x11},
				{0x02, 0x12},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := transpose(tt.args.chunks); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("transpose() = %v, want %v", got, tt.want)
			}
		})
	}

}

func TestKeyCandidate_findBest(t *testing.T) {

	msg := "a very important message. keep it private and safe. for reals"
	key := "secret"

	enc, err := XorEncrypt([]byte(msg), []byte(key))
	require.NoError(t, err)

	kc := &KeyCandidate{
		Length: len(key),
		val:    make([]byte, len(key)),
	}
	kc.findBest(enc)

	require.Equal(t, key, string(kc.val), "key, val")
}

func TestSet1Challenge6(t *testing.T) {

	t.Run("simple", func(t *testing.T) {
		msg := "a very important message. keep it private and safe. oh well nevermind"
		key := "secret"

		enc, err := XorEncrypt([]byte(msg), []byte(key))
		require.NoError(t, err)
		v := &Vigenere{
			candidates: 5,
			minKeyLen:  3,
			maxKeyLen:  10,
			nBlocks:    2,
		}
		r, err := v.Decrypt(enc)

		require.NoError(t, err)
		assert.Equal(t, key, string(r.Key))
		t.Logf("got key %s data %s", string(r.Key), r.Output)

	})

	t.Run("set 1 challenge 6", func(t *testing.T) {
		b64, err := os.ReadFile("testdata/6.txt")
		require.NoError(t, err)

		enc, err := base64.StdEncoding.DecodeString(string(b64))
		require.NoError(t, err)

		v := &Vigenere{
			candidates: 38,
			minKeyLen:  2,
			maxKeyLen:  40,
			nBlocks:    2,
		}
		r, err := v.Decrypt(enc)

		require.NoError(t, err)
		assert.Equal(t, "Terminator X: Bring the noise", string(r.Key))
		t.Logf("got key %s data %s", string(r.Key), r.Output)

	})
}

func Test_rankKeyLengths(t *testing.T) {
	type args struct {
		//		data    []byte
		msg     string
		key     string
		min     int
		max     int
		nBlocks int
		nSizes  int
	}
	tests := []struct {
		name    string
		args    args
		wantLen int
		wantErr bool
	}{
		{
			name: "d i",
			args: args{
				msg:     `We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.--That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, --That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness.`,
				key:     "a mer i ca",
				min:     2,
				max:     24,
				nBlocks: 10,
				nSizes:  8,
			},
			wantLen: len("a mer i ca"),
		},

		{
			name: "genesis",
			args: args{
				msg: `[1:1] In the beginning when God created the heavens and the earth,
				[1:2] the earth was a formless void and darkness covered the face of the deep, while a wind from God swept over the face of the waters.
				[1:3] Then God said, "Let there be light"; and there was light.
				[1:4] And God saw that the light was good; and God separated the light from the darkness.
				[1:5] God called the light Day, and the darkness he called Night. And there was evening and there was morning, the first day.
				[1:6] And God said, "Let there be a dome in the midst of the waters, and let it separate the waters from the waters."
				[1:7] So God made the dome and separated the waters that were under the dome from the waters that were above the dome. And it was so.
				[1:8] God called the dome Sky. And there was evening and there was morning, the second day.
				[1:9] And God said, "Let the waters under the sky be gathered together into one place, and let the dry land appear." And it was so.
				[1:10] God called the dry land Earth, and the waters that were gathered together he called Seas. And God saw that it was good.
				[1:11] Then God said, "Let the earth put forth vegetation: plants yielding seed, and fruit trees of every kind on earth that bear fruit with the seed in it." And it was so.
				[1:12] The earth brought forth vegetation: plants yielding seed of every kind, and trees of every kind bearing fruit with the seed in it. And God saw that it was good.
				[1:13] And there was evening and there was morning, the third day.
				[1:14] And God said, "Let there be lights in the dome of the sky to separate the day from the night; and let them be for signs and for seasons and for days and years,
				[1:15] and let them be lights in the dome of the sky to give light upon the earth." And it was so.
				[1:16] God made the two great lights - the greater light to rule the day and the lesser light to rule the night - and the stars.
				[1:17] God set them in the dome of the sky to give light upon the earth,
				[1:18] to rule over the day and over the night, and to separate the light from the darkness. And God saw that it was good.
				[1:19] And there was evening and there was morning, the fourth day.
				[1:20] And God said, "Let the waters bring forth swarms of living creatures, and let birds fly above the earth across the dome of the sky."
				[1:21] So God created the great sea monsters and every living creature that moves, of every kind, with which the waters swarm, and every winged bird of every kind. And God saw that it was good.
				[1:22] God blessed them, saying, "Be fruitful and multiply and fill the waters in the seas, and let birds multiply on the earth."
				[1:23] And there was evening and there was morning, the fifth day.
				[1:24] And God said, "Let the earth bring forth living creatures of every kind: cattle and creeping things and wild animals of the earth of every kind." And it was so.
				[1:25] God made the wild animals of the earth of every kind, and the cattle of every kind, and everything that creeps upon the ground of every kind. And God saw that it was good.
				[1:26] Then God said, "Let us make humankind in our image, according to our likeness; and let them have dominion over the fish of the sea, and over the birds of the air, and over the cattle, and over all the wild animals of the earth, and over every creeping thing that creeps upon the earth."
				[1:27] So God created humankind in his image, in the image of God he created them; male and female he created them.
				[1:28] God blessed them, and God said to them, "Be fruitful and multiply, and fill the earth and subdue it; and have dominion over the fish of the sea and over the birds of the air and over every living thing that moves upon the earth."
				[1:29] God said, "See, I have given you every plant yielding seed that is upon the face of all the earth, and every tree with seed in its fruit; you shall have them for food.
				[1:30] And to every beast of the earth, and to every bird of the air, and to everything that creeps on the earth, everything that has the breath of life, I have given every green plant for food." And it was so.
				[1:31] God saw everything that he had made, and indeed, it was very good. And there was evening and there was morning, the sixth day.`,
				key:     "Genesis Chapter 1",
				min:     2,
				max:     40,
				nBlocks: 4,
				nSizes:  8,
			},
			wantLen: len("Genesis Chapter 1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := XorEncrypt([]byte(tt.args.msg), []byte(tt.args.key))
			require.NoError(t, err)
			got, err := rankKeyLengths(enc, tt.args.min, tt.args.max, tt.args.nBlocks)
			if (err != nil) != tt.wantErr {
				t.Errorf("rankKeyLengths() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			bestLengths := make([]int, tt.args.nSizes)
			for i := 0; i < tt.args.nSizes; i++ {
				t.Logf("best %d: %+v", i, *got[i])
				bestLengths[i] = got[i].Length
			}
			assert.Contains(t, bestLengths, tt.wantLen)

		})
	}
}

func TestSet1Challenge7(t *testing.T) {
	b64, err := os.ReadFile("testdata/7.txt")
	require.NoError(t, err)

	enc, err := base64.StdEncoding.DecodeString(string(b64))
	require.NoError(t, err)
	key := []byte("YELLOW SUBMARINE")
	fixedKey := (*[16]byte)(key)
	txt, err := AES128ECB(enc, *fixedKey)
	require.NoError(t, err)
	assert.Contains(t, string(txt), "Play that funky music")
}
