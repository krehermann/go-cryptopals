package utils

import (
	"reflect"
	"testing"
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
					[]byte{0x00, 0x01, 0x02},
					[]byte{0x10, 0x11, 0x12},
				},
			},
			want: [][]byte{
				[]byte{0x00, 0x10},
				[]byte{0x01, 0x11},
				[]byte{0x02, 0x12},
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
