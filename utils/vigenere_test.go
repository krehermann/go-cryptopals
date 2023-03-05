package utils

import (
	"reflect"
	"testing"

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
