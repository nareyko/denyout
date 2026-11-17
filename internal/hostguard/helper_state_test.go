package hostguard

import "testing"

func TestHelperStateRoundTripAndValidation(t *testing.T) {
	spec := Spec{ProxyPort: 18443, UID: 1000, AllowQUIC: true, TunTCP: true, TunV6Guard: true, TunV6DropQUIC: true}
	b, err := encodeHelperState(spec)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeHelperState(b, 1000)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TunTCP || got.TunV6Guard || got.TunV6DropQUIC {
		t.Error("transient TUN suppression flags must not be persisted/restored")
	}
	if !got.AllowQUIC || got.ProxyPort != 18443 || got.UID != 1000 {
		t.Errorf("user intent lost: %+v", got)
	}
	for name, tc := range map[string]struct {
		b     []byte
		owner int
	}{
		"wrong owner": {b, 1001},
		"no owner":    {b, 0},
		"empty":       {nil, 1000},
		"junk":        {[]byte("{not json"), 1000},
		"huge":        {make([]byte, 70<<10), 1000},
	} {
		if _, err := decodeHelperState(tc.b, tc.owner); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	bad, _ := encodeHelperState(Spec{ProxyPort: 70000, UID: 1000})
	if _, err := decodeHelperState(bad, 1000); err == nil {
		t.Error("bad port accepted")
	}
	evil, _ := encodeHelperState(Spec{ProxyPort: 1, UID: 1000, CACert: "/etc/shadow"})
	if _, err := decodeHelperState(evil, 1000); err == nil {
		t.Error("CA path outside policy accepted")
	}
}
