package jsonstrict

import (
	"strings"
	"testing"
)

type payload struct {
	Token string `json:"token"`
	Nonce string `json:"nonce"`
}

func TestDecodeRejectsAmbiguousOrMalformedJSON(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
		want    string
	}{
		{
			name: "well formed",
			body: `{"token":"a","nonce":"n"}`,
			want: "a",
		},
		{
			// v1 acceptait et retenait "b" : différentiel de parseur si
			// l'origine, elle, retient "a".
			name:    "duplicate member name",
			body:    `{"token":"a","token":"b","nonce":"n"}`,
			wantErr: true,
		},
		{
			// v1 acceptait et remplaçait par U+FFFD, altérant la valeur inspectée.
			name:    "invalid utf-8 in string",
			body:    "{\"token\":\"a\xed\xa0\x80\",\"nonce\":\"n\"}",
			wantErr: true,
		},
		{
			name:    "unknown member",
			body:    `{"token":"a","nonce":"n","extra":1}`,
			wantErr: true,
		},
		{
			// Comportement v1 délibérément préservé : les clients existants qui
			// varient la casse ne doivent pas casser.
			name: "case-insensitive member name",
			body: `{"Token":"a","NONCE":"n"}`,
			want: "a",
		},
		{
			// Comme Decoder.Decode : on lit une valeur, pas jusqu'à EOF.
			name: "trailing content after the first value",
			body: `{"token":"a","nonce":"n"} trailing`,
			want: "a",
		},
		{
			name:    "not json",
			body:    `nope`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got payload
			err := Decode(strings.NewReader(tt.body), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Decode() expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode() unexpected error = %v", err)
			}
			if got.Token != tt.want {
				t.Fatalf("token = %q, want %q", got.Token, tt.want)
			}
		})
	}
}

func TestUnmarshalAppliesTheSameGuards(t *testing.T) {
	var got payload
	if err := Unmarshal([]byte(`{"token":"a","token":"b"}`), &got); err == nil {
		t.Fatal("Unmarshal() accepted a duplicate member name")
	}
	if err := Unmarshal([]byte(`{"token":"a"}`), &got); err != nil {
		t.Fatalf("Unmarshal() unexpected error = %v", err)
	}
	if got.Token != "a" {
		t.Fatalf("token = %q, want \"a\"", got.Token)
	}
}
