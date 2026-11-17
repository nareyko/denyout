package threatlists

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte("0.0.0.0 evil.example\n# c\n||ads.example^\n"), 0)
	f.Add([]byte("\x00\xff\r\n\r\n   "), 1)
	f.Fuzz(func(t *testing.T, data []byte, mode int) {
		for _, fm := range []Format{FormatDomains} {
			_ = Parse(data, fm)
		}
		_ = mode
	})
}
