package tun

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

// QUICAction is what to do with a UDP/443 flow after sighting.
type QUICAction string

const (
	QUICActionDrop  QUICAction = "drop"
	QUICActionSight QUICAction = "sight"
	QUICActionMITM  QUICAction = "mitm"
)

// QUICDecision is returned by a QUICInspector.
type QUICDecision struct {
	Action QUICAction
	SNI    string
	Reason string
}

// QUICInspector chooses Drop / Sight / MITM for a UDP/443 datagram.
type QUICInspector interface {
	Decide(ctx context.Context, udpPayload []byte) QUICDecision
}

// DefaultQUICInspector implements Q1 sighting and optional Q2 MITM gate.
type DefaultQUICInspector struct {
	MITM bool // WantQUICMITM or pref
}

// cursorQUICPassthrough mirrors proxy.TLSPassthroughHost (avoid import cycle).
func cursorQUICPassthrough(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h == "cursor.sh" || strings.HasSuffix(h, ".cursor.sh") ||
		h == "cursor.com" || strings.HasSuffix(h, ".cursor.com")
}

// Decide extracts SNI when possible; MITM only when enabled (implementation in quic_mitm_*).
func (d DefaultQUICInspector) Decide(ctx context.Context, udpPayload []byte) QUICDecision {
	_ = ctx
	sight, ok := SightQUICInitial(udpPayload)
	sni := sight.SNI
	if d.MITM {
		if cursorQUICPassthrough(sni) {
			return QUICDecision{Action: QUICActionDrop, SNI: sni, Reason: "cursor_passthrough_no_quic_mitm"}
		}
		return QUICDecision{Action: QUICActionMITM, SNI: sni, Reason: "quic_mitm"}
	}
	if ok && sight.HasSNI {
		return QUICDecision{Action: QUICActionSight, SNI: sni, Reason: "quic_sight"}
	}
	if ok {
		return QUICDecision{Action: QUICActionDrop, SNI: sni, Reason: "quic_drop_no_sni"}
	}
	return QUICDecision{Action: QUICActionDrop, Reason: "quic_drop"}
}

// ErrQUICMITMNotReady is returned when MITM is requested but the session layer fails.
var ErrQUICMITMNotReady = fmt.Errorf("tun: quic mitm not ready")

// MITMConfig carries CA material for QUIC terminate/reencrypt.
type MITMConfig struct {
	GetCertificate     func(chi *tls.ClientHelloInfo) (*tls.Certificate, error)
	RootCAs            *x509.CertPool // for dialing origin (system + optional)
	InsecureSkipVerify bool           // lab origins only
}
