package utils

import (
	"encoding/hex"
	"reflect"
	"testing"

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
