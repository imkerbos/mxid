package auditsink

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// collector is a stand-in syslog server speaking RFC 6587 octet counting.
type collector struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
	done chan struct{}
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	c := &collector{ln: ln, done: make(chan struct{})}
	go c.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return c
}

func (c *collector) addr() string { return c.ln.Addr().String() }

func (c *collector) serve() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return
		}
		go c.read(conn)
	}
}

func (c *collector) read(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		// "<len> <msg>"
		lenStr, err := r.ReadString(' ')
		if err != nil {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(lenStr))
		if err != nil || n <= 0 {
			return
		}
		buf := make([]byte, n)
		if _, err := readFull(r, buf); err != nil {
			return
		}
		c.mu.Lock()
		c.msgs = append(c.msgs, string(buf))
		c.mu.Unlock()
	}
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	got := 0
	for got < len(buf) {
		n, err := r.Read(buf[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func (c *collector) received() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.msgs...)
}

func (c *collector) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.received(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("collector received %d message(s), want %d", len(c.received()), n)
	return nil
}

func sampleRecord(id int64) Record {
	actor := int64(7)
	return Record{
		ID:        id,
		TenantID:  1,
		Time:      time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC),
		EventType: "user.deleted",
		Success:   true,
		ActorID:   &actor,
		ActorName: "admin",
		IP:        "203.0.113.9",
		Detail:    json.RawMessage(`{"user_id":42}`),
	}
}

func TestSinkForwardsToCollector(t *testing.T) {
	col := newCollector(t)
	s, err := New(Config{Addr: col.addr(), Proto: ProtoTCP, Facility: 13, Hostname: "node-1"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close(context.Background()) }()

	s.Forward(sampleRecord(1001))
	got := col.waitFor(t, 1)[0]

	// <PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID SD MSG
	// facility 13 * 8 + severity 6 (info) = 110
	if !strings.HasPrefix(got, "<110>1 ") {
		t.Errorf("priority/version header wrong: %q", got[:min(24, len(got))])
	}
	for _, want := range []string{"node-1", DefaultAppName, "user.deleted"} {
		if !strings.Contains(got, want) {
			t.Errorf("message is missing %q: %s", want, got)
		}
	}

	body := got[strings.Index(got, "{"):]
	var rec Record
	if err := json.Unmarshal([]byte(body), &rec); err != nil {
		t.Fatalf("body is not the record as JSON: %v\n%s", err, body)
	}
	if rec.ID != 1001 || rec.ActorName != "admin" || rec.IP != "203.0.113.9" {
		t.Errorf("record did not survive the round trip: %+v", rec)
	}
}

// A failed action arrives a severity above a successful one so a collector can
// key a rule on it without parsing the body.
func TestSeverityDistinguishesFailure(t *testing.T) {
	col := newCollector(t)
	s, _ := New(Config{Addr: col.addr(), Proto: ProtoTCP, Facility: 13}, nil)
	defer func() { _ = s.Close(context.Background()) }()

	fail := sampleRecord(1)
	fail.Success = false
	s.Forward(fail)

	got := col.waitFor(t, 1)[0]
	// 13*8 + 4 (warning) = 108
	if !strings.HasPrefix(got, "<108>") {
		t.Errorf("a failed action did not arrive at warning severity: %q", got[:min(12, len(got))])
	}
}

// THE property that matters. Forwarding runs on the audit write path, which is
// synchronous with every write API in the product: if a stalled collector could
// make Forward block, an unreachable log server would take the whole service
// down. Overflow must drop and count, never wait.
func TestForwardNeverBlocksWhenQueueIsFull(t *testing.T) {
	// A collector that accepts the connection and then never reads, so the
	// worker wedges on the socket and the queue fills behind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		<-make(chan struct{}) // never read, never close
		_ = conn
	}()

	s, err := New(Config{Addr: ln.Addr().String(), Proto: ProtoTCP, Facility: 13, QueueSize: 4}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close(context.Background()) }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 500 {
			s.Forward(sampleRecord(int64(i)))
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Forward blocked — a stalled collector can stall every write API in the product")
	}

	_, dropped, _ := s.Stats()
	if dropped == 0 {
		t.Error("nothing was counted as dropped, so overflow is going unreported")
	}
}

// A nil Sink is what a deployment with no collector configured gets, so every
// call site would otherwise need a nil check on the audit write path.
func TestNilSinkIsUsable(t *testing.T) {
	var s *Sink
	s.Forward(sampleRecord(1))
	s.SetMetrics(nil, nil, nil)
	if f, d, x := s.Stats(); f != 0 || d != 0 || x != 0 {
		t.Errorf("stats on a nil sink = %d/%d/%d, want zeroes", f, d, x)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Errorf("Close on a nil sink: %v", err)
	}
}

func TestNewWithoutAddrIsDisabledNotAnError(t *testing.T) {
	s, err := New(Config{Addr: ""}, nil)
	if err != nil {
		t.Fatalf("no collector configured should not be an error: %v", err)
	}
	if s != nil {
		t.Error("want a nil sink when no collector is configured")
	}
}

func TestNewRejectsUnknownProtocol(t *testing.T) {
	if _, err := New(Config{Addr: "127.0.0.1:514", Proto: "carrier-pigeon"}, nil); err == nil {
		t.Error("an unsupported protocol was accepted")
	}
}

// Header fields are space-delimited, so a value carrying a space would shift
// every field after it and hand a caller control of how the collector parses
// the message.
func TestHeaderFieldsCannotBreakFraming(t *testing.T) {
	rec := sampleRecord(1)
	rec.EventType = "evil type\nwith newline"
	msg := rec.format(13, "host name", DefaultAppName, time.Now())

	header := msg[:strings.Index(msg, "{")]
	if n := strings.Count(header, " "); n != 7 {
		t.Errorf("header has %d spaces, want exactly 7 delimiters: %q", n, header)
	}
	if strings.Contains(header, "\n") {
		t.Errorf("a newline reached the header: %q", header)
	}
}

func TestSanitizeHeaderEmptyBecomesNilValue(t *testing.T) {
	for _, in := range []string{"", "   ", "\x00\x01"} {
		if got := sanitizeHeader(in); got != nilValue {
			t.Errorf("sanitizeHeader(%q) = %q, want %q", in, got, nilValue)
		}
	}
}

func TestUDPTransport(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer func() { _ = pc.Close() }()

	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 8192)
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		got <- string(buf[:n])
	}()

	s, err := New(Config{Addr: pc.LocalAddr().String(), Proto: ProtoUDP, Facility: 13}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	s.Forward(sampleRecord(2002))

	select {
	case msg := <-got:
		// A datagram has its own boundary, so it must NOT carry the octet count
		// that stream framing needs.
		if !strings.HasPrefix(msg, "<110>1 ") {
			t.Errorf("UDP datagram is not a bare syslog message: %q", msg[:min(24, len(msg))])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no datagram arrived")
	}
}
