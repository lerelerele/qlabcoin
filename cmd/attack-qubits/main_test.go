package main

import (
	"reflect"
	"testing"
)

func TestReorderFlags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "level before flag",
			in:   []string{"5", "-solution", "36"},
			want: []string{"-solution", "36", "5"},
		},
		{
			name: "flags already first",
			in:   []string{"-solution", "36", "5"},
			want: []string{"-solution", "36", "5"},
		},
		{
			name: "equals form is self-contained",
			in:   []string{"5", "-solution=36"},
			want: []string{"-solution=36", "5"},
		},
		{
			name: "multiple flags interleaved",
			in:   []string{"5", "-solution", "36", "-circuit", "sha256:abc"},
			want: []string{"-solution", "36", "-circuit", "sha256:abc", "5"},
		},
		{
			name: "two positionals no flags",
			in:   []string{"5", "hardened"},
			want: []string{"5", "hardened"},
		},
		{
			name: "trailing flag without value consumes nothing",
			in:   []string{"-list"},
			want: []string{"-list"},
		},
		{
			name: "empty input",
			in:   nil,
			want: nil,
		},
		{
			// Documented limitation: a token starting with '-' after a flag is
			// treated as another flag, never as that flag's value.
			name: "dash-prefixed value is not consumed as value",
			in:   []string{"-solution", "-1", "5"},
			want: []string{"-solution", "-1", "5"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reorderFlags(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("reorderFlags(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestContainsEqual(t *testing.T) {
	if !containsEqual("-solution=36") {
		t.Fatal("expected '=' to be detected")
	}
	if containsEqual("-solution") {
		t.Fatal("did not expect '=' in a bare flag")
	}
}
