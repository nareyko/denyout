package tun_test

import (
	"testing"

	"github.com/nareyko/denyout/internal/tun"
)

func TestSightQUICFindsSNIInTLSRecord(t *testing.T) {
	sni := []byte("example.com")
	ext := []byte{
		0x00, 0x00,
		0x00, byte(5 + len(sni)),
		0x00, byte(3 + len(sni)),
		0x00,
		byte(len(sni) >> 8), byte(len(sni)),
	}
	ext = append(ext, sni...)
	ch := []byte{0x01, 0x00, 0x00, 0x00}
	ch = append(ch, 0x03, 0x03)
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0x00)
	ch = append(ch, 0x00, 0x02, 0x00, 0x2f)
	ch = append(ch, 0x01, 0x00)
	ch = append(ch, byte(len(ext)>>8), byte(len(ext)))
	ch = append(ch, ext...)
	hsLen := len(ch) - 4
	ch[1] = byte(hsLen >> 16)
	ch[2] = byte(hsLen >> 8)
	ch[3] = byte(hsLen)
	rec := []byte{0x16, 0x03, 0x01, byte(len(ch) >> 8), byte(len(ch))}
	rec = append(rec, ch...)

	got, ok := tun.SightQUICInitial(rec)
	if !ok || !got.HasSNI || got.SNI != "example.com" {
		t.Fatalf("got=%+v ok=%v", got, ok)
	}
}

func TestWantQUICMITMDefaultOff(t *testing.T) {
	t.Setenv(tun.EnvQUICMITM, "")
	if tun.WantQUICMITM() {
		t.Fatal("default off")
	}
	t.Setenv(tun.EnvQUICMITM, "1")
	if !tun.WantQUICMITM() {
		t.Fatal("opt-in")
	}
}

func TestDefaultQUICInspectorSight(t *testing.T) {
	insp := tun.DefaultQUICInspector{MITM: false}
	dec := insp.Decide(nil, []byte{0xc0, 0x00, 0x00, 0x00, 0x01})
	if dec.Action != tun.QUICActionDrop && dec.Action != tun.QUICActionSight {
		t.Fatalf("%+v", dec)
	}
	insp.MITM = true
	dec = insp.Decide(nil, []byte("x"))
	if dec.Action != tun.QUICActionMITM && dec.Action != tun.QUICActionDrop {
		t.Fatalf("%+v", dec)
	}
}
