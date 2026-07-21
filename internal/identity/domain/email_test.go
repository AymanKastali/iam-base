package domain

import "testing"

func TestNewEmail(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"valid lowercase", "a@b.com", "a@b.com", false},
		{"normalizes case", "A@B.COM", "a@b.com", false},
		{"trims whitespace", "  a@b.com  ", "a@b.com", false},
		{"rejects empty", "", "", true},
		{"rejects missing @", "ab.com", "", true},
		{"rejects missing domain", "a@", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := NewEmail(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewEmail(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if !tt.wantErr && e.String() != tt.want {
				t.Errorf("NewEmail(%q).String() = %q, want %q", tt.raw, e.String(), tt.want)
			}
		})
	}
}
