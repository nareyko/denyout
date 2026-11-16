package tun

import (
	"encoding/binary"
)

// QUICSight is a best-effort view of an Initial/0-RTT UDP/443 packet (no decrypt).
type QUICSight struct {
	SNI     string
	HasSNI  bool
	Version uint32
}

// SightQUICInitial tries to extract TLS SNI from a QUIC Initial ClientHello crypto frame.
// Returns ok=false when the packet is not parseable (still DropLog).
func SightQUICInitial(udpPayload []byte) (QUICSight, bool) {
	var out QUICSight
	if len(udpPayload) < 1 {
		return out, false
	}
	// Best-effort SNI scan first (cleartext lab / coalesced CRYPTO).
	if sni, ok := extractTLSSNI(udpPayload); ok {
		out.SNI = sni
		out.HasSNI = true
	}
	// Long header: header form bit set → treat as QUIC Initial-ish.
	if udpPayload[0]&0x80 == 0 {
		return out, out.HasSNI
	}
	if len(udpPayload) < 7 {
		return out, out.HasSNI
	}
	out.Version = binary.BigEndian.Uint32(udpPayload[1:5])
	return out, true
}

// extractTLSSNI finds server_name in a TLS ClientHello blob (best-effort scan).
func extractTLSSNI(buf []byte) (string, bool) {
	// Look for handshake type client_hello (1) after content type 22.
	for i := 0; i+5 < len(buf); i++ {
		if buf[i] != 0x16 { // handshake record
			continue
		}
		if i+5 >= len(buf) {
			break
		}
		recLen := int(buf[i+3])<<8 | int(buf[i+4])
		start := i + 5
		end := start + recLen
		if end > len(buf) {
			end = len(buf)
		}
		if start >= end || buf[start] != 0x01 { // client_hello
			continue
		}
		if sni, ok := parseClientHelloSNI(buf[start:end]); ok {
			return sni, true
		}
	}
	// Also try raw ClientHello without record layer.
	if len(buf) > 4 && buf[0] == 0x01 {
		if sni, ok := parseClientHelloSNI(buf); ok {
			return sni, true
		}
	}
	return "", false
}

func parseClientHelloSNI(ch []byte) (string, bool) {
	// HandshakeType(1) + len(3) + version(2) + random(32) + session_id
	if len(ch) < 39 {
		return "", false
	}
	i := 4 // skip type+len
	i += 2 // version
	i += 32
	if i >= len(ch) {
		return "", false
	}
	sidLen := int(ch[i])
	i++
	i += sidLen
	if i+2 > len(ch) {
		return "", false
	}
	csLen := int(ch[i])<<8 | int(ch[i+1])
	i += 2 + csLen
	if i >= len(ch) {
		return "", false
	}
	compLen := int(ch[i])
	i++
	i += compLen
	if i+2 > len(ch) {
		return "", false
	}
	extLen := int(ch[i])<<8 | int(ch[i+1])
	i += 2
	end := i + extLen
	if end > len(ch) {
		end = len(ch)
	}
	for i+4 <= end {
		typ := int(ch[i])<<8 | int(ch[i+1])
		l := int(ch[i+2])<<8 | int(ch[i+3])
		i += 4
		if i+l > end {
			break
		}
		if typ == 0 && l >= 5 { // server_name
			// list_len(2) + name_type(1) + name_len(2) + name
			j := i + 2
			if j+3 > i+l {
				break
			}
			if ch[j] != 0 {
				break
			}
			j++
			nlen := int(ch[j])<<8 | int(ch[j+1])
			j += 2
			if j+nlen > i+l {
				break
			}
			return string(ch[j : j+nlen]), true
		}
		i += l
	}
	return "", false
}
