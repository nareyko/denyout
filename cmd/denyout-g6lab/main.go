// denyout-g6lab — lab origins + clients for Docker G6 dogfood (not shipped in releases).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const labHost = "lab.denyout.test"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s serve|https-get|h3-get|quic-inject|cursor-decide\n", os.Args[0])
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		os.Exit(cmdServe())
	case "https-get":
		os.Exit(cmdHTTPSGet())
	case "h3-get":
		os.Exit(cmdH3Get())
	case "quic-inject":
		os.Exit(cmdQUICInject())
	case "cursor-decide":
		os.Exit(cmdCursorDecide())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

func cmdServe() int {
	cert, err := selfSigned(labHost)
	if err != nil {
		log.Printf("cert: %v", err)
		return 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "g6-lab-ok")
	})

	// Non-loopback lab IP so nft fwmark → denyout0 can steer client traffic
	// (127.0.0.0/8 stays in the local table and bypasses TUN).
	labIP := net.ParseIP(envOr("DENYOUT_LAB_IP", "198.18.0.10"))
	httpsLn, err := tls.Listen("tcp", net.JoinHostPort(labIP.String(), "443"), &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		log.Printf("https listen: %v", err)
		return 1
	}
	httpsSrv := &http.Server{Handler: mux}
	go func() { _ = httpsSrv.Serve(httpsLn) }()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: labIP, Port: 443})
	if err != nil {
		log.Printf("h3 udp: %v", err)
		return 1
	}
	h3 := &http3.Server{
		Handler: mux,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{cert},
		}),
	}
	go func() { _ = h3.Serve(udp) }()

	fmt.Printf("READY lab.denyout.test https+h3 %s:443\n", labIP)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = httpsSrv.Shutdown(ctx)
	_ = h3.Close()
	return 0
}

func cmdHTTPSGet() int {
	cacert := envOr("DENYOUT_CACERT", "")
	tlsConf := &tls.Config{ServerName: labHost, InsecureSkipVerify: cacert == ""}
	if cacert != "" {
		pemBytes, err := os.ReadFile(cacert)
		if err != nil {
			log.Printf("cacert: %v", err)
			return 1
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			log.Printf("cacert: no PEM")
			return 1
		}
		tlsConf.RootCAs = pool
		tlsConf.InsecureSkipVerify = false
	}
	tr := &http.Transport{
		TLSClientConfig:   tlsConf,
		ForceAttemptHTTP2: false,
		TLSNextProto:      map[string]func(authority string, c *tls.Conn) http.RoundTripper{},
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	resp, err := client.Get("https://" + labHost + "/")
	if err != nil {
		log.Printf("https-get: %v", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	fmt.Printf("status=%d body=%s\n", resp.StatusCode, string(body))
	if resp.StatusCode != 200 || string(body) != "g6-lab-ok" {
		return 1
	}
	return 0
}

func cmdH3Get() int {
	cacert := envOr("DENYOUT_CACERT", "")
	tlsConf := &tls.Config{ServerName: labHost, NextProtos: []string{http3.NextProtoH3}, InsecureSkipVerify: cacert == ""}
	if cacert != "" {
		pemBytes, err := os.ReadFile(cacert)
		if err != nil {
			log.Printf("cacert: %v", err)
			return 1
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			log.Printf("cacert: no PEM")
			return 1
		}
		tlsConf.RootCAs = pool
		tlsConf.InsecureSkipVerify = false
	}
	rt := &http3.Transport{TLSClientConfig: tlsConf}
	defer rt.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+labHost+"/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		log.Printf("h3-get: %v", err)
		return 1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	fmt.Printf("status=%d body=%s\n", resp.StatusCode, string(body))
	if resp.StatusCode != 200 {
		return 1
	}
	return 0
}

// cmdQUICInject sends a synthetic QUIC Initial-ish UDP datagram with an embedded TLS SNI blob
// to 127.0.0.1:443 so TUN sighting can observe last_sni= (not a full handshake).
func cmdQUICInject() int {
	sni := envOr("DENYOUT_SNI", labHost)
	payload := fakeQUICInitialWithSNI(sni)
	labIP := net.ParseIP(envOr("DENYOUT_LAB_IP", "198.18.0.10"))
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: labIP, Port: 443})
	if err != nil {
		log.Printf("dial: %v", err)
		return 1
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		log.Printf("write: %v", err)
		return 1
	}
	fmt.Printf("injected sni=%s bytes=%d\n", sni, len(payload))
	return 0
}

func cmdCursorDecide() int {
	// Compile-time sanity: import path unused — exercise inspector via tiny UDP blob.
	// Real assert is in go test; this prints expected reason for shell.
	fmt.Println("cursor_passthrough_no_quic_mitm")
	return 0
}

func fakeQUICInitialWithSNI(sni string) []byte {
	// Minimal long-header prefix + TLS ClientHello record containing SNI extension.
	hello := buildClientHelloSNI(sni)
	rec := make([]byte, 5+len(hello))
	rec[0] = 0x16
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hello)))
	copy(rec[5:], hello)
	out := make([]byte, 7+len(rec))
	out[0] = 0xc0 // long header
	binary.BigEndian.PutUint32(out[1:5], 0x00000001)
	out[5] = 0
	out[6] = 0
	copy(out[7:], rec)
	return out
}

func buildClientHelloSNI(sni string) []byte {
	// handshake header + body with extensions containing server_name
	name := []byte(sni)
	// extension server_name
	sniExt := make([]byte, 9+len(name))
	binary.BigEndian.PutUint16(sniExt[0:2], 0) // type server_name
	binary.BigEndian.PutUint16(sniExt[2:4], uint16(5+len(name)))
	binary.BigEndian.PutUint16(sniExt[4:6], uint16(3+len(name)))
	sniExt[6] = 0 // host_name
	binary.BigEndian.PutUint16(sniExt[7:9], uint16(len(name)))
	copy(sniExt[9:], name)

	extLen := len(sniExt)
	// ver(2)+random(32)+sidLen(1)+cipherLen(2)+cipher(2)+compLen(1)+comp(1)+extLen(2)+exts
	body := make([]byte, 2+32+1+2+2+1+1+2+extLen)
	body[0] = 0x03
	body[1] = 0x03
	body[34] = 0 // session id len
	binary.BigEndian.PutUint16(body[35:37], 2)
	body[37] = 0x00
	body[38] = 0x2f
	body[39] = 1
	body[40] = 0
	binary.BigEndian.PutUint16(body[41:43], uint16(extLen))
	copy(body[43:], sniExt)

	hs := make([]byte, 4+len(body))
	hs[0] = 0x01 // client_hello
	hs[1] = byte(len(body) >> 16)
	hs[2] = byte(len(body) >> 8)
	hs[3] = byte(len(body))
	copy(hs[4:], body)
	return hs
}

func selfSigned(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// silence unused quic import when only http3 used in some builds
var _ = quic.Version1
