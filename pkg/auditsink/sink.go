package auditsink

import (
	"context"
	"crypto/tls"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// DefaultQueueSize bounds how far the forwarder may fall behind the audit path
// before it starts dropping. Large enough to ride out a collector restart or a
// burst; small enough that a collector down for an hour costs bounded memory
// rather than the process.
const DefaultQueueSize = 4096

// DefaultAppName is the syslog APP-NAME audit records are tagged with.
const DefaultAppName = "mxid-audit"

// Config describes where audit records are mirrored to.
type Config struct {
	// Addr is host:port of the collector. Empty disables forwarding entirely.
	Addr string
	// Proto is udp, tcp or tcp+tls.
	Proto string
	// Facility is the syslog facility number. 13 (log audit) is the one
	// reserved for exactly this, and collectors route on it.
	Facility int
	// Hostname identifies this replica in the stream. Empty uses the OS name.
	Hostname string
	// AppName tags the stream. Empty uses DefaultAppName.
	AppName string
	// QueueSize bounds the buffer. Zero uses DefaultQueueSize.
	QueueSize int
	// TLS configures tcp+tls. Ignored for the other transports.
	TLS *tls.Config
}

// Sink mirrors audit records to a collector. The zero value is not usable; a
// nil *Sink is, and forwards nothing — that is what a deployment with no
// collector configured gets, so callers never need to nil-check.
type Sink struct {
	cfg    Config
	w      *syslogWriter
	logger *zap.Logger

	queue chan Record
	wg    sync.WaitGroup
	stop  chan struct{}
	once  sync.Once

	dropped   atomic.Int64
	failed    atomic.Int64
	forwarded atomic.Int64

	// onDrop and onFail report to metrics. Injected rather than imported so
	// this package stays free of the metrics registry and is testable without
	// one.
	onDrop func()
	onFail func()
	onSent func()
}

// New builds a Sink. Returns (nil, nil) when Addr is empty: no collector
// configured is a valid deployment, not an error.
func New(cfg Config, logger *zap.Logger) (*Sink, error) {
	if cfg.Addr == "" {
		return nil, nil
	}
	w, err := newSyslogWriter(ParseProto(cfg.Proto), cfg.Addr, cfg.TLS)
	if err != nil {
		return nil, err
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}
	if cfg.AppName == "" {
		cfg.AppName = DefaultAppName
	}

	s := &Sink{
		cfg:    cfg,
		w:      w,
		logger: logger,
		queue:  make(chan Record, cfg.QueueSize),
		stop:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.run()
	return s, nil
}

// SetMetrics wires counters for forwarded / dropped / failed records.
func (s *Sink) SetMetrics(sent, dropped, failed func()) {
	if s == nil {
		return
	}
	s.onSent, s.onDrop, s.onFail = sent, dropped, failed
}

// Forward queues a record. It NEVER blocks and never returns an error: the
// audit write it accompanies has already committed, and making the caller wait
// on a collector would put a remote host in the critical path of every write
// API in the product. An overflowing queue drops the record and counts it —
// the database still holds it, so what is lost is the mirror's completeness,
// which the counter is there to report.
func (s *Sink) Forward(rec Record) {
	if s == nil {
		return
	}
	select {
	case s.queue <- rec:
	default:
		n := s.dropped.Add(1)
		if s.onDrop != nil {
			s.onDrop()
		}
		// One line per power-of-two dropped, not one per drop: a collector that
		// stops reading would otherwise turn a full queue into a log flood,
		// which is its own outage.
		if s.logger != nil && isPowerOfTwo(n) {
			s.logger.Warn("audit forwarding queue full — record not mirrored",
				zap.Int64("dropped_total", n),
				zap.String("collector", s.cfg.Addr),
				zap.String("note", "the record is still in the database; only the external copy was lost"))
		}
	}
}

func (s *Sink) run() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			// Drain what is already queued so a clean shutdown does not throw
			// away records that were accepted.
			for {
				select {
				case rec := <-s.queue:
					s.send(rec)
				default:
					return
				}
			}
		case rec := <-s.queue:
			s.send(rec)
		}
	}
}

func (s *Sink) send(rec Record) {
	msg := rec.format(s.cfg.Facility, s.cfg.Hostname, s.cfg.AppName, time.Now())
	if err := s.w.write(msg); err != nil {
		n := s.failed.Add(1)
		if s.onFail != nil {
			s.onFail()
		}
		if s.logger != nil && isPowerOfTwo(n) {
			s.logger.Warn("audit forwarding failed",
				zap.Int64("failed_total", n),
				zap.String("collector", s.cfg.Addr),
				zap.Error(err))
		}
		return
	}
	s.forwarded.Add(1)
	if s.onSent != nil {
		s.onSent()
	}
}

// Stats reports counts since start: records mirrored, dropped for queue
// overflow, and failed at the transport.
func (s *Sink) Stats() (forwarded, dropped, failed int64) {
	if s == nil {
		return 0, 0, 0
	}
	return s.forwarded.Load(), s.dropped.Load(), s.failed.Load()
}

// Close drains the queue and releases the connection. Safe to call twice.
func (s *Sink) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.once.Do(func() { close(s.stop) })

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		// Shutdown is bounded: a collector that will not accept the backlog
		// must not hold up the process exit.
	}
	return s.w.Close()
}

func isPowerOfTwo(n int64) bool { return n > 0 && n&(n-1) == 0 }
