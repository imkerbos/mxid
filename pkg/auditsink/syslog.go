package auditsink

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Transport names accepted in configuration.
const (
	ProtoUDP    = "udp"
	ProtoTCP    = "tcp"
	ProtoTCPTLS = "tcp+tls"
)

const dialTimeout = 5 * time.Second

// syslogWriter is a reconnecting syslog client.
//
// UDP is fire-and-forget by nature: a write that "succeeds" proves nothing
// arrived. TCP tells the truth about delivery but needs the connection managed,
// and TLS is the only one of the three safe to send audit records over a link
// you do not control — the records carry usernames and addresses.
type syslogWriter struct {
	proto     string
	addr      string
	tlsConfig *tls.Config

	mu   sync.Mutex
	conn net.Conn
}

func newSyslogWriter(proto, addr string, tlsConfig *tls.Config) (*syslogWriter, error) {
	switch proto {
	case ProtoUDP, ProtoTCP, ProtoTCPTLS:
	default:
		return nil, fmt.Errorf("unsupported syslog protocol %q (want %s, %s or %s)",
			proto, ProtoUDP, ProtoTCP, ProtoTCPTLS)
	}
	if addr == "" {
		return nil, fmt.Errorf("syslog address is empty")
	}
	return &syslogWriter{proto: proto, addr: addr, tlsConfig: tlsConfig}, nil
}

func (w *syslogWriter) dial() (net.Conn, error) {
	switch w.proto {
	case ProtoUDP:
		return net.DialTimeout("udp", w.addr, dialTimeout)
	case ProtoTCP:
		return net.DialTimeout("tcp", w.addr, dialTimeout)
	case ProtoTCPTLS:
		return tls.DialWithDialer(&net.Dialer{Timeout: dialTimeout}, "tcp", w.addr, w.tlsConfig)
	}
	return nil, fmt.Errorf("unsupported syslog protocol %q", w.proto)
}

// write sends one message, reconnecting once if the existing connection has
// gone away. A collector restart is routine, and one silent retry is the
// difference between losing a batch of records and losing none.
func (w *syslogWriter) write(msg string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.writeLocked(msg); err == nil {
		return nil
	} else if w.proto == ProtoUDP {
		// Nothing to reconnect: a UDP socket does not fail because the peer
		// went away, so an error here is local and retrying will not help.
		return err
	}

	w.closeLocked()
	if err := w.writeLocked(msg); err != nil {
		return err
	}
	return nil
}

func (w *syslogWriter) writeLocked(msg string) error {
	if w.conn == nil {
		conn, err := w.dial()
		if err != nil {
			return fmt.Errorf("dial syslog %s/%s: %w", w.proto, w.addr, err)
		}
		w.conn = conn
	}

	_ = w.conn.SetWriteDeadline(time.Now().Add(dialTimeout))

	var payload string
	if w.proto == ProtoUDP {
		payload = msg
	} else {
		// RFC 6587 octet counting. A stream has no datagram boundaries, so the
		// collector needs to be told where each message ends; the alternative
		// (newline framing) breaks the moment a field contains a newline, and
		// user agents do.
		payload = fmt.Sprintf("%d %s", len(msg), msg)
	}

	if _, err := w.conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("write syslog: %w", err)
	}
	return nil
}

func (w *syslogWriter) closeLocked() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}

func (w *syslogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeLocked()
	return nil
}

// ParseProto normalises a configured protocol name.
func ParseProto(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
