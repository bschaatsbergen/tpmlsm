package main

import "testing"

func TestParseAllowlist(t *testing.T) {
	const sum = "97e1fc0f22d92de63204eec74076a003d1ca820d1d6db3c8fde3227f1ca7f4fc"

	tests := []struct {
		name    string
		in      string
		want    []string // expected paths, in order
		wantErr bool
	}{
		{name: "empty", in: "", want: nil},
		{name: "comments only", in: "# nothing\n\n", want: nil},
		{name: "bare digest", in: sum + "\n", wantErr: true},
		{name: "sha256sum format", in: sum + "  /usr/bin/tpm2\n", want: []string{"/usr/bin/tpm2"}},
		{name: "short digest", in: "abcd\n", wantErr: true},
		{name: "not hex", in: "zz" + sum[2:] + "\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowlist([]byte(tt.in))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d entries, want %d", len(got), len(tt.want))
			}
			for i, a := range got {
				if a.name != tt.want[i] {
					t.Errorf("entry %d name = %q, want %q", i, a.name, tt.want[i])
				}
			}
		})
	}
}
